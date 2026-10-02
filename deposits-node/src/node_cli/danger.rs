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
        "fork-update" => danger_fork_update(&args[1..]).await,
        "forge-non-conforming-cosig" => danger_forge_non_conforming_cosig(&args[1..]).await,
        cmd => {
            eprintln!("Unknown danger subcommand: {}", cmd);
            eprintln!(
                "Available: publish-invalid, forge-stale-cosig, fork-update, \
                 forge-non-conforming-cosig"
            );
            Ok(())
        }
    }
}

/// Mint one `SignedLedgerUpdate` that's non-conforming under the
/// active ruleset — operator-signed plus forged cosignatures from
/// passed-in seeds. Witness for
/// `FraudProofType::NonConformingCosignature`.
///
/// In production a cosigner runs check_conformance and refuses to
/// sign anything that fires a `ConformanceViolation`. This command
/// short-circuits that gate by forging cosigs directly; the resulting
/// update is exactly the artifact the cosigners *should* have
/// refused but (per the fraud-proof framing) didn't.
///
/// The forged op is an `InvoiceLock { amount: 0, deposit_id:
/// dummy, … }`. Either path lands fraud:
///   - apply succeeds → conformance flags `ZeroAmount`.
///   - apply fails (dummy deposit_id unknown) → state machine
///     refuses outright; the verifier treats apply-Err as fraud
///     since the cosigners signed an unapplyable op.
///
/// Usage: `danger forge-non-conforming-cosig <reserves_id>
///         [--cosigner-seed <hex>]+`
async fn danger_forge_non_conforming_cosig(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::types::CosignEntry;
    use deposits_core::SignedLedgerUpdate;
    use deposits_core::TlvEncode;
    use sha2::{Digest, Sha256};

    if args.is_empty() {
        eprintln!(
            "Usage: deposits-node danger forge-non-conforming-cosig \
             <reserves_id> [--cosigner-seed <hex>]+"
        );
        return Ok(());
    }

    let reserves_id = &args[0];

    // Pull --cosigner-seed values out separately from config args.
    let mut cosigner_seeds: Vec<[u8; 32]> = Vec::new();
    let mut config_args = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--cosigner-seed" && i + 1 < args.len() {
            let raw = hex::decode(&args[i + 1])
                .map_err(|e| format!("--cosigner-seed must be 64-char hex: {}", e))?;
            let arr: [u8; 32] = raw
                .try_into()
                .map_err(|_| "--cosigner-seed must be 32 bytes")?;
            cosigner_seeds.push(arr);
            i += 2;
            continue;
        }
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            config_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first().ok_or("No relay configured")?.clone();

    let secp = Secp256k1::new();
    let operator_secret = super::derive_operator_secret(&config.seed, config.network)?;
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let operator_pubkey = operator_keypair.public_key();

    let node = Node::new(config).await?;
    let (_ledger_id_hex, ledger) = node
        .get_ledger_with_id(reserves_id)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;
    let last = ledger
        .history
        .last()
        .ok_or("Ledger has no history")?
        .clone();
    let next_seq = last.sequence_number + 1;
    let prev_chain_hash = last.chain_hash();

    let active_member_pks: Vec<bitcoin::secp256k1::PublicKey> = ledger
        .state
        .quorum_members
        .iter()
        .map(|m| m.pubkey)
        .collect();
    let threshold = (active_member_pks.len() / 2) + 1;

    let mut active_cosigners: Vec<(Keypair, bitcoin::secp256k1::PublicKey)> = Vec::new();
    for seed in &cosigner_seeds {
        let sk = super::derive_operator_secret(seed, bitcoin::Network::Regtest)?;
        let kp = Keypair::from_secret_key(&secp, &sk);
        let pk = kp.public_key();
        if active_member_pks.contains(&pk) {
            active_cosigners.push((kp, pk));
        }
    }
    if active_cosigners.len() < threshold {
        return Err(format!(
            "need {} cosigner-seed(s) matching the ledger's {} quorum members; \
             got {} matching seeds",
            threshold,
            active_member_pks.len(),
            active_cosigners.len()
        )
        .into());
    }
    active_cosigners.truncate(threshold);

    // Build the non-conforming InvoiceLock. amount=0 trips ZeroAmount
    // if apply succeeds; otherwise the dummy deposit_id makes apply
    // fail outright (also a fraud verdict in the verifier).
    let dummy_deposit_id = deposits_core::types::DepositId::from([0u8; 16]);
    let bad_op = LedgerOperation::InvoiceLock {
        deposit_id: dummy_deposit_id,
        amount: 0,
        payment_id: [0xCD; 32],
        sequence_number: next_seq,
        nonce: 1,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        commitment: None,
        witness: deposits_core::DescriptorWitness::default(),
    };
    let message = bad_op.tlv_encode();
    let message_type = LedgerOperation::message_type_from_bytes(&message);

    let mut update = SignedLedgerUpdate {
        message,
        message_type,
        operator_id: operator_pubkey,
        ledger_id: ledger.state.ledger_id,
        sequence_number: next_seq,
        previous_hash: prev_chain_hash,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    let cosign_msg = Message::from_digest(update.cosign_digest(&[0u8; 32]));
    update.cosignatures = active_cosigners
        .iter()
        .map(|(kp, pk)| CosignEntry {
            cosigner_pubkey: *pk,
            cosign_signature: secp.sign_schnorr_no_aux_rand(&cosign_msg, kp).serialize(),
            member_ledger_hash: [0u8; 32],
        })
        .collect();
    update.cosignatures.sort_by(|a, b| {
        a.cosigner_pubkey
            .serialize()
            .cmp(&b.cosigner_pubkey.serialize())
    });
    update.content_hash = update.compute_hash();

    let op_msg = Message::from_digest(update.operator_digest());
    update.operator_signature = secp
        .sign_schnorr_no_aux_rand(&op_msg, &operator_keypair)
        .serialize();

    println!(
        "Forged non-conforming update at seq={} prev_hash={}",
        next_seq,
        hex::encode(prev_chain_hash)
    );
    println!("U content_hash={}", hex::encode(update.content_hash));
    // Full TLV bytes for the test's NonConformingCosignature evidence
    // builder (the cosigner daemons will reject this update at apply
    // time, so reading it back off disk doesn't work — the relay
    // does carry it; we surface it here for the test's convenience).
    println!("U tlv_hex={}", hex::encode(update.tlv_encode()));
    for (_, pk) in &active_cosigners {
        println!("Forged cosig from pubkey={}", hex::encode(pk.serialize()));
    }

    let transport = NostrTransportBuilder::new(operator_secret)
        .relay(&relay_url)
        .build()
        .await?;
    let event_id = transport.broadcast_ledger_update(&update).await?;
    println!("Broadcast forged update: {}", event_id);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    transport.disconnect().await;

    Ok(())
}

/// Mint two `SignedLedgerUpdate`s at the same `{sequence, previous_hash}`
/// with different message content, both signed by the operator and
/// cosigned by majority of the operator's quorum (using cosigner seeds
/// passed as `--cosigner-seed <hex>`). Broadcasts U_A first, waits, then
/// broadcasts U_B.
///
/// Honest quorum members ingest U_A and apply it to their replicas. By
/// the time U_B arrives, their `chain_tip_hash` matches `U_A.chain_hash()`,
/// so U_B fails the chain-continuity check (`previous_hash` doesn't match)
/// and is rejected. Anyone who collects both U_A and U_B has cryptographic
/// evidence of operator equivocation — the witness for a future
/// `FraudProofType::Equivocation`.
///
/// The "as of now" semantics: any seq later than the equivocation point
/// continues to extend U_A's chain (U_A is what cosigners signed and
/// applied). Late discovery of U_B is evidence of past misbehavior, not
/// grounds for unwinding the chain — chain rewriting would invalidate
/// downstream legitimate operations.
///
/// Usage: `danger fork-update <reserves_id> [--cosigner-seed <hex>]+`
async fn danger_fork_update(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::types::CosignEntry;
    use deposits_core::SignedLedgerUpdate;
    use deposits_core::TlvEncode;
    use sha2::{Digest, Sha256};

    if args.is_empty() {
        eprintln!("Usage: deposits-node danger fork-update <reserves_id> [--cosigner-seed <hex>]+");
        return Ok(());
    }

    let reserves_id = &args[0];

    // Pull --cosigner-seed values out separately from other config args.
    let mut cosigner_seeds: Vec<[u8; 32]> = Vec::new();
    let mut config_args = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--cosigner-seed" && i + 1 < args.len() {
            let raw = hex::decode(&args[i + 1])
                .map_err(|e| format!("--cosigner-seed must be 64-char hex: {}", e))?;
            let arr: [u8; 32] = raw
                .try_into()
                .map_err(|_| "--cosigner-seed must be 32 bytes")?;
            cosigner_seeds.push(arr);
            i += 2;
            continue;
        }
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            config_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first().ok_or("No relay configured")?.clone();
    let data_dir = config.data_dir.clone();

    let secp = Secp256k1::new();
    let operator_secret = super::derive_operator_secret(&config.seed, config.network)?;
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let operator_pubkey = operator_keypair.public_key();

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

    // Match cosigner seeds against the active quorum members so we only
    // sign with seeds that actually correspond to a member.
    let active_member_pks: Vec<bitcoin::secp256k1::PublicKey> = ledger
        .state
        .quorum_members
        .iter()
        .map(|m| m.pubkey)
        .collect();
    let threshold = (active_member_pks.len() / 2) + 1;

    let mut active_cosigners: Vec<(Keypair, bitcoin::secp256k1::PublicKey)> = Vec::new();
    for seed in &cosigner_seeds {
        let sk = super::derive_operator_secret(seed, bitcoin::Network::Regtest)?;
        let kp = Keypair::from_secret_key(&secp, &sk);
        let pk = kp.public_key();
        if active_member_pks.contains(&pk) {
            active_cosigners.push((kp, pk));
        }
    }
    if active_cosigners.len() < threshold {
        return Err(format!(
            "need {} cosigner-seed(s) matching the ledger's {} quorum members; \
             got {} matching seeds",
            threshold,
            active_member_pks.len(),
            active_cosigners.len()
        )
        .into());
    }
    // Use only the threshold-many cosigners — the bare minimum for a
    // valid update. This makes the equivocation construction precise:
    // both U_A and U_B carry the same set of cosigner signatures.
    active_cosigners.truncate(threshold);

    // Build the two competing messages — DeliveryEmbed with different
    // request_hash bytes so the message body diverges (and so does
    // content_hash, even with identical {seq, prev_hash, cosigs}).
    let msg_a = LedgerOperation::DeliveryEmbed {
        request_hash: [0xAA; 32],
        target_ledger_id: ledger.state.ledger_id,
        target_operator: operator_pubkey,
    }
    .tlv_encode();
    let msg_b = LedgerOperation::DeliveryEmbed {
        request_hash: [0xBB; 32],
        target_ledger_id: ledger.state.ledger_id,
        target_operator: operator_pubkey,
    }
    .tlv_encode();

    // Helper: produce a fully-signed SignedLedgerUpdate at the given
    // {next_seq, prev_chain_hash} with the supplied message body.
    let build_update = |message: Vec<u8>, message_type: u16| -> SignedLedgerUpdate {
        let mut update = SignedLedgerUpdate {
            message,
            message_type,
            operator_id: operator_pubkey,
            ledger_id: ledger.state.ledger_id,
            sequence_number: next_seq,
            previous_hash: prev_chain_hash,
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        };
        let cosign_msg = Message::from_digest(update.cosign_digest(&[0u8; 32]));
        update.cosignatures = active_cosigners
            .iter()
            .map(|(kp, pk)| CosignEntry {
                cosigner_pubkey: *pk,
                cosign_signature: secp.sign_schnorr_no_aux_rand(&cosign_msg, kp).serialize(),
                member_ledger_hash: [0u8; 32], // not relevant for this scenario
            })
            .collect();
        // Canonical sort to match what receivers expect on TLV decode.
        update.cosignatures.sort_by(|a, b| {
            a.cosigner_pubkey
                .serialize()
                .cmp(&b.cosigner_pubkey.serialize())
        });
        update.content_hash = update.compute_hash();

        // Operator sign over content + all cosigs
        let op_msg = Message::from_digest(update.operator_digest());
        update.operator_signature = secp
            .sign_schnorr_no_aux_rand(&op_msg, &operator_keypair)
            .serialize();

        update
    };

    let message_type = deposits_core::messages::LedgerOperation::message_type_from_bytes(&msg_a);
    let update_a = build_update(msg_a, message_type);
    let update_b = build_update(msg_b, message_type);

    println!(
        "Forked updates at seq={} prev_hash={}",
        next_seq,
        hex::encode(prev_chain_hash)
    );
    // Full hashes on dedicated, parseable lines so an integration test
    // can pull them out of stdout deterministically.
    println!("U_A content_hash={}", hex::encode(update_a.content_hash));
    println!("U_A chain_hash={}", hex::encode(update_a.chain_hash()));
    println!("U_B content_hash={}", hex::encode(update_b.content_hash));
    println!("U_B chain_hash={}", hex::encode(update_b.chain_hash()));
    // Full TLV bytes (hex) for both updates. The equivocation
    // fraud-proof test reads these from stdout to build the
    // `FraudEvidence::Equivocation` payload — fetching them back off
    // the relay isn't reliable because cosigners only persist the
    // first one that applies and reject the second at the
    // ledger_actor edge (it never makes it to disk).
    println!("U_A tlv_hex={}", hex::encode(update_a.tlv_encode()));
    println!("U_B tlv_hex={}", hex::encode(update_b.tlv_encode()));

    let transport = NostrTransportBuilder::new(operator_secret)
        .relay(&relay_url)
        .build()
        .await?;

    let event_a = transport.broadcast_ledger_update(&update_a).await?;
    println!("Broadcast U_A: {}", event_a);
    // Give honest quorum members time to ingest U_A and advance their
    // replicas; U_B arrives after the chain_tip_hash has moved past.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let event_b = transport.broadcast_ledger_update(&update_b).await?;
    println!("Broadcast U_B: {}", event_b);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    transport.disconnect().await;
    let _ = (data_dir, ledger_id); // step 3: own-ledger inbound is no longer skipped

    Ok(())
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
    let relay_url = config.relays.first().ok_or("No relay configured")?.clone();
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
        operator_signature: [0u8; 64],
        cosignatures,
    };
    update.content_hash = update.compute_hash();
    let content_hash = update.content_hash;

    // Sign with operator's key over the v2 operator digest.
    let msg = Message::from_digest(update.operator_digest());
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
    println!("  Content:     {}...", &hex::encode(content_hash)[..16]);
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
    let _ = (data_dir, ledger_id); // step 3: own-ledger inbound is no longer skipped

    println!("Broadcast: {}", event_id);
    Ok(())
}

/// Publish an invalid ledger update to test recovery mechanisms.
/// WARNING: This creates non-conforming updates that break protocol rules.
async fn danger_publish_invalid(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use deposits_core::SignedLedgerUpdate;
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

            // Build the update with a WRONG previous_hash (the fraud) but an
            // otherwise well-formed body: a valid content_hash and a REAL
            // operator signature over the canonical v2 digest. A faithful
            // malicious operator signs correctly with their own key — the
            // fault is that the update doesn't chain onto the canonical tip.
            // (The old bespoke signing digest matched no format the protocol
            // accepts, so verify_operator_signature rejected it and the
            // NonConformingUpdate confiscation verifier could never ground.)
            let mut update = SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: new_seq,
                previous_hash: wrong_prev_hash,
                content_hash: [0u8; 32],
                block_height: 0,
                block_hash: [0u8; 32],
                operator_signature: [0u8; 64],
                cosignatures: Vec::new(),
            };
            update.content_hash = update.compute_hash();
            let digest = update.operator_digest();
            let sig = secp.sign_schnorr(&Message::from_digest(digest), &secret_key.keypair(&secp));
            update.operator_signature = sig.serialize();
            update
        }

        "skip-sequence" => {
            let skipped_seq = current_seq + 5;

            let dummy_message = vec![0u8; 8];
            let message_type: u16 = 0x0001;

            let mut update = SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: skipped_seq,
                previous_hash: content_hash,
                content_hash: [0u8; 32],
                block_height: 0,
                block_hash: [0u8; 32],
                operator_signature: [0u8; 64],
                cosignatures: Vec::new(),
            };
            update.content_hash = update.compute_hash();
            let message = Message::from_digest(update.operator_digest());
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            update.operator_signature = sig.serialize();
            update
        }

        "replay" => {
            if ledger.history.len() < 2 {
                return Err("Need at least 2 updates to create replay attack".into());
            }

            let old_update = &ledger.history[ledger.history.len() / 2];
            let mut replayed = old_update.clone();

            let message = Message::from_digest(replayed.operator_digest());
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
    // Give the relay pool time to flush before tearing down the WebSocket.
    // `broadcast_ledger_update` returns when the EVENT is QUEUED, not when
    // strfry has acknowledged it; disconnecting sub-millisecond later drops
    // the forged update before the relay stores it — so `recovery start`
    // and the confiscation-time inline-evidence fetch never see it. Same
    // flush the fork-update path performs.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
        obj.insert(
            "type".to_string(),
            serde_json::Value::String("Update".into()),
        );
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
