use bitcoin::secp256k1::Secp256k1;

use super::deposit::{add_offer, open_new_deposit};
use super::{
    deposit_record_identity, derive_secret_key, derive_secret_key_at_index, parse_config,
    NostrTransportBuilder,
};

/// Withdraw from a deposit
pub async fn withdraw(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut destination: Option<String> = None;
    let mut fee_sats: u64 = 500; // Default fee
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" if i + 1 < args.len() => {
                destination = Some(args[i + 1].clone());
                i += 1;
            }
            "--fee" if i + 1 < args.len() => {
                fee_sats = args[i + 1].parse()?;
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or(
        "Usage: deposits-wallet withdraw <alias> <amount_sats> --to <address> --relay <url>",
    )?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let destination = destination.ok_or("Missing destination. Use --to <address>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| {
            format!(
                "No deposit found with alias '{}'. Use 'list' to see your deposits.",
                alias
            )
        })?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    // Get the key_index for this deposit (defaults to 0 for legacy deposits)
    let key_index = deposit
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);

    // Use nostr identity key (index 0) for transport signing
    let nostr_key = config.nostr_key()?;

    // Source the descriptor of truth from the deposit record. The
    // `deposit_id` is its hash; the witness is whatever satisfies
    // the descriptor over `withdrawal_signing_message`.
    let (descriptor, deposit_id_hex) = deposit_record_identity(deposit)
        .ok_or("Deposit record missing descriptor / deposit_pubkey — re-open this deposit")?;
    let deposit_id_bytes =
        hex::decode(&deposit_id_hex).map_err(|e| format!("Bad stored deposit_id: {}", e))?;
    let mut deposit_id = [0u8; 16];
    deposit_id.copy_from_slice(&deposit_id_bytes);

    // Generate nonce (becomes withdrawal_id when hashed)
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    // Sign the WITHDRAWAL message (nonce, deposit_id, address, amount, fee).
    // For pk(...) descriptors the witness is a single Schnorr sig; multi(...)
    // would push N sigs in stack order.
    let msg_hash = deposits_core::signature_utils::withdrawal_signing_message(
        &nonce,
        &deposit_id,
        &destination,
        amount_sats,
        fee_sats,
    );
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.serialize().to_vec()],
    };

    println!("Withdrawal Request");
    println!("==================");
    println!("  Alias: {}", alias);
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    println!("  To: {}", destination);
    println!();

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "descriptor": descriptor,
        "address": destination,
        "amount_sats": amount_sats,
        "fee_sats": fee_sats,
        "nonce": hex::encode(nonce),
        "witness": witness,
    });

    println!("Sending signed withdrawal request...");

    let request_id = transport
        .send_ledger_request(ledger_id, "withdraw", request_params)
        .await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Wait for response using real-time subscription
    println!("Waiting for operator response...");

    match transport.wait_for_response(&request_id, 60000).await {
        Ok(response) => {
            if response.success {
                println!("Withdrawal accepted!");
                if let Some(result) = &response.result {
                    if let Some(withdrawal_id) =
                        result.get("withdrawal_id").and_then(|v| v.as_str())
                    {
                        println!("  Withdrawal ID: {}", withdrawal_id);
                    }
                    if let Some(message) = result.get("message").and_then(|v| v.as_str()) {
                        println!("  {}", message);
                    }
                }
                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Withdrawal failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for operator response: {}", e).into()),
    }
}

/// Lock funds for a conditional transfer (HTLC-style)
///
/// Creates a TransferLock with a hash-lock completion script.
/// The recipient can complete the transfer by revealing the preimage.
pub async fn transfer_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut dest_deposit_id: Option<String> = None;
    let mut hash_hex: Option<String> = None;
    let mut timeout_height: Option<u32> = None;
    // If --fee isn't supplied, compute from TransferFeeSchedule::default()
    // (fixed_msats=2, rate_bps=20) against the transfer amount below.
    let mut fee_msats_override: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" if i + 1 < args.len() => {
                dest_deposit_id = Some(args[i + 1].clone());
                i += 1;
            }
            "--hash" if i + 1 < args.len() => {
                hash_hex = Some(args[i + 1].clone());
                i += 1;
            }
            "--timeout" if i + 1 < args.len() => {
                timeout_height = Some(args[i + 1].parse()?);
                i += 1;
            }
            "--fee" if i + 1 < args.len() => {
                fee_msats_override = Some(args[i + 1].parse()?);
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or(
        "Usage: deposits-wallet transfer <alias> <amount_sats> --to <dest_id> --hash <sha256> --timeout <block> [--fee <msats>] --relay <url>"
    )?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let dest_deposit_id_hex =
        dest_deposit_id.ok_or("Missing destination. Use --to <deposit_id>")?;
    let hash_hex = hash_hex.ok_or("Missing hash lock. Use --hash <sha256_hex>")?;
    let timeout_height = timeout_height.ok_or("Missing timeout. Use --timeout <block_height>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Parse destination deposit_id
    let dest_bytes = hex::decode(&dest_deposit_id_hex)?;
    if dest_bytes.len() != 16 {
        return Err("Destination deposit_id must be 32 hex chars (16 bytes)".into());
    }
    let mut dest_id = [0u8; 16];
    dest_id.copy_from_slice(&dest_bytes);

    // Parse hash lock
    let hash_bytes = hex::decode(&hash_hex)?;
    if hash_bytes.len() != 32 {
        return Err("Hash must be 64 hex chars (32 bytes)".into());
    }
    let completion_script = format!("sha256({})", hash_hex);

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| {
            format!(
                "No deposit found with alias '{}'. Use 'list' to see your deposits.",
                alias
            )
        })?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    let key_index = deposit
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    let nostr_key = config.nostr_key()?;

    // Compute source deposit_id
    let descriptor = format!("pk({})", hex::encode(our_pubkey.serialize()));
    let source_id = deposits_core::types::compute_deposit_id(&descriptor);

    // Generate nonce
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    // Convert to msats for signing and request
    let amount_msats = amount_sats * 1000;

    // Resolve fee: use --fee if supplied, otherwise compute from the default
    // TransferFeeSchedule (fixed_msats=2, rate_bps=20 per core.rs).
    let fee_msats = match fee_msats_override {
        Some(f) => f,
        None => {
            let default = deposits_core::types::TransferFeeSchedule::default();
            default
                .fixed_msats
                .saturating_add(amount_msats.saturating_mul(default.rate_bps as u64) / 10_000)
        }
    };

    // Compute signing message and transfer_id (all in msats)
    let msg_hash = deposits_core::signature_utils::transfer_lock_signing_message(
        &nonce,
        &source_id,
        &dest_id,
        amount_msats,
        fee_msats,
        &completion_script,
        timeout_height,
    );
    let transfer_id = deposits_core::signature_utils::compute_transfer_id(&msg_hash);

    // Sign
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &keypair);

    println!("Transfer Lock Request");
    println!("=====================");
    println!(
        "  Source:      {} ({})",
        alias,
        hex::encode(&source_id[..4])
    );
    println!("  Destination: {}", dest_deposit_id_hex);
    println!(
        "  Amount:      {} sats ({} msats)",
        amount_sats, amount_msats
    );
    println!("  Fee:         {} msats", fee_msats);
    println!(
        "  Hash Lock:   {}...{}",
        &hash_hex[..8],
        &hash_hex[hash_hex.len() - 8..]
    );
    println!("  Timeout:     block {}", timeout_height);
    println!("  Transfer ID: {}", hex::encode(transfer_id));
    println!();

    // Connect to relay
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Set response filter for relay-side #l tag filtering (reduces fan-out)
    transport.set_response_ledger_filter(vec![ledger_id.to_string()]);

    let request_params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(source_id),
        "destination_deposit_id": hex::encode(dest_id),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

    println!("Sending transfer lock request...");

    let request_id = transport
        .send_ledger_request(ledger_id, "transfer_lock", request_params)
        .await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Wait for response using real-time subscription (much faster than polling)
    match transport.wait_for_response(&request_id, 10000).await {
        Ok(response) => {
            if response.success {
                println!("  Transfer ID: {}", hex::encode(transfer_id));
                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Transfer lock failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for operator response: {}", e).into()),
    }
}

/// Complete a transfer by revealing the preimage
pub async fn transfer_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut transfer_id_hex: Option<String> = None;
    let mut preimage_hex: Option<String> = None;
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preimage" if i + 1 < args.len() => {
                preimage_hex = Some(args[i + 1].clone());
                i += 1;
            }
            "--ledger" if i + 1 < args.len() => {
                ledger_id = Some(args[i + 1].clone());
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if transfer_id_hex.is_none() {
                    transfer_id_hex = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let transfer_id_hex = transfer_id_hex.ok_or(
        "Usage: deposits-wallet transfer_complete <transfer_id> --preimage <hex> --ledger <id> --relay <url>"
    )?;
    let preimage_hex = preimage_hex.ok_or("Missing preimage. Use --preimage <hex>")?;
    let ledger_id = ledger_id.ok_or("Missing ledger. Use --ledger <ledger_id>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Parse transfer_id
    let transfer_bytes = hex::decode(&transfer_id_hex)?;
    if transfer_bytes.len() != 32 {
        return Err("Transfer ID must be 64 hex chars (32 bytes)".into());
    }
    let mut transfer_id = [0u8; 32];
    transfer_id.copy_from_slice(&transfer_bytes);

    // Parse preimage
    let preimage_bytes = hex::decode(&preimage_hex)?;
    if preimage_bytes.len() != 32 {
        return Err("Preimage must be 64 hex chars (32 bytes)".into());
    }

    println!("Transfer Complete Request");
    println!("=========================");
    println!("  Transfer ID: {}...", &transfer_id_hex[..16]);
    println!("  Preimage:    {}...", &preimage_hex[..16]);
    println!();

    // Connect to relay
    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Set response filter for relay-side #l tag filtering (reduces fan-out)
    transport.set_response_ledger_filter(vec![ledger_id.clone()]);

    let request_params = serde_json::json!({
        "transfer_id": transfer_id_hex,
        "preimage": preimage_hex,
    });

    println!("Sending transfer complete request...");

    let request_id = transport
        .send_ledger_request(&ledger_id, "transfer_complete", request_params)
        .await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Wait for response using real-time subscription (much faster than polling)
    match transport.wait_for_response(&request_id, 10000).await {
        Ok(response) => {
            if response.success {
                println!("Transfer completed!");
                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Transfer complete failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for operator response: {}", e).into()),
    }
}

/// Route a transfer across ledgers via a courier (DEP-13)
///
/// Usage: deposits-wallet route <from-alias> <to-alias> <amount_sats> --relay <url> [--relay <url>...]
pub async fn route_transfer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    use deposits_core::signature_utils::{compute_transfer_id, transfer_lock_signing_message};
    use deposits_core::types::compute_deposit_id;

    let mut from_alias: Option<String> = None;
    let mut to_alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
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
                if from_alias.is_none() {
                    from_alias = Some(args[i].clone());
                } else if to_alias.is_none() {
                    to_alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let from_alias =
        from_alias.ok_or("Usage: deposits-wallet route <from> <to> <amount_sats> --relay <url>")?;
    let to_alias = to_alias.ok_or("Missing destination alias")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Load deposits
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create deposits first.".into());
    }
    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let from_dep = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&from_alias))
        .ok_or_else(|| format!("No deposit '{}'. Use 'list' to see deposits.", from_alias))?;
    let to_dep = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&to_alias))
        .ok_or_else(|| format!("No deposit '{}'. Use 'list' to see deposits.", to_alias))?;

    let from_ledger = from_dep["ledger_id"]
        .as_str()
        .ok_or("Missing ledger_id on source")?;
    let to_ledger = to_dep["ledger_id"]
        .as_str()
        .ok_or("Missing ledger_id on dest")?;

    if from_ledger == to_ledger {
        return Err("Source and destination are on the same ledger. Use 'transfer' for same-ledger transfers.".into());
    }

    let from_key_index = from_dep
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let to_key_index = to_dep
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let from_secret = derive_secret_key_at_index(&config.seed, config.network, from_key_index)?;
    let from_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &from_secret);
    let from_pubkey = from_keypair.public_key();
    let from_descriptor = format!("pk({})", hex::encode(from_pubkey.serialize()));
    let from_deposit_id = compute_deposit_id(&from_descriptor);

    let to_secret = derive_secret_key_at_index(&config.seed, config.network, to_key_index)?;
    let to_pubkey = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &to_secret).public_key();
    let to_descriptor = format!("pk({})", hex::encode(to_pubkey.serialize()));
    let to_deposit_id = compute_deposit_id(&to_descriptor);
    let to_deposit_id_hex = hex::encode(to_deposit_id);

    let amount_msats = amount_sats * 1000;

    // Connect to relays
    let nostr_key = config.nostr_key()?;
    let mut transport = NostrTransportBuilder::new(nostr_key);
    for r in &config.relays {
        transport = transport.relay(r);
    }
    let transport = transport.build().await?;

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    // Also connect to operator relays from advertisements so requests reach operators
    let op_ads = transport.fetch_ledger_advertisements(network_str).await?;
    for ad in &op_ads {
        if let Some(ref relay_url) = ad.relay_url {
            if !config.relays.contains(relay_url) {
                let _ = transport.add_relay(relay_url).await;
            }
        }
    }

    // Step 1: Find a courier that bridges both ledgers
    println!("Finding courier...");
    let agent_ads = transport.fetch_agent_advertisements(network_str).await?;
    let courier = agent_ads
        .iter()
        .find(|ad| {
            ad.ledgers.iter().any(|l| l.ledger_id == from_ledger)
                && ad.ledgers.iter().any(|l| l.ledger_id == to_ledger)
        })
        .ok_or_else(|| {
            format!(
                "No courier bridges {} and {}. Run 'discover' to check available couriers.",
                &from_ledger[..8],
                &to_ledger[..8]
            )
        })?;

    let src_entry = courier
        .ledgers
        .iter()
        .find(|l| l.ledger_id == from_ledger)
        .unwrap();
    let dst_entry = courier
        .ledgers
        .iter()
        .find(|l| l.ledger_id == to_ledger)
        .unwrap();
    let fee_in = src_entry.fee_in_fixed_msats + amount_msats * src_entry.fee_in_rate_bps / 10000;
    let fee_out = dst_entry.fee_out_fixed_msats + amount_msats * dst_entry.fee_out_rate_bps / 10000;
    let route_fee = fee_in + fee_out;
    let forward = amount_msats.saturating_sub(route_fee);

    println!("  Courier: {}...", &courier.agent_pubkey[..16]);
    println!(
        "  Route fee: {} msats (in={}, out={})",
        route_fee, fee_in, fee_out
    );
    println!("  Forward:  {} msats ({} sats)", forward, forward / 1000);
    println!();

    // Step 2: Generate preimage and request route
    println!("Requesting route...");
    let mut rng = OsRng;
    let mut preimage = [0u8; 32];
    rng.fill_bytes(&mut preimage);
    let hash: [u8; 32] = {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let mut engine = sha256::Hash::engine();
        engine.input(&preimage);
        sha256::Hash::from_engine(engine).to_byte_array()
    };
    let hash_hex = hex::encode(hash);

    let route_req = serde_json::json!({
        "source_ledger": from_ledger,
        "dest_ledger": to_ledger,
        "dest_deposit_id": to_deposit_id_hex,
        "amount_msats": amount_msats,
        "hash": hash_hex,
    });

    let req_id = transport
        .send_agent_request(&courier.agent_pubkey, "request_route", route_req)
        .await?;
    let route_resp = transport.wait_for_response(&req_id, 15000).await?;
    if !route_resp.success {
        return Err(format!(
            "Courier rejected route: {}",
            route_resp.error.unwrap_or_default()
        )
        .into());
    }

    let result = route_resp
        .result
        .ok_or("Missing result in route response")?;
    let courier_deposit_id_hex = result["courier_deposit_id"]
        .as_str()
        .ok_or("Missing courier_deposit_id in response")?;
    let courier_deposit_id = hex::decode(courier_deposit_id_hex)?;
    if courier_deposit_id.len() != 16 {
        return Err("Invalid courier_deposit_id length".into());
    }
    let mut dest_id = [0u8; 16];
    dest_id.copy_from_slice(&courier_deposit_id);

    println!("  Courier deposit: {}", courier_deposit_id_hex);
    println!();

    // Step 3: Lock transfer to courier
    println!("Locking transfer to courier...");

    // Get block height from a balance query
    transport.set_response_ledger_filter(vec![from_ledger.to_string(), to_ledger.to_string()]);
    let from_deposit_id_hex_str = deposit_record_identity(from_dep)
        .map(|(_, id)| id)
        .ok_or("From-deposit record missing descriptor / deposit_pubkey")?;
    let balance_req = serde_json::json!({
        "deposit_id": from_deposit_id_hex_str,
    });
    let bal_req_id = transport
        .send_ledger_request(from_ledger, "balance_query", balance_req)
        .await?;
    let bal_resp = transport.wait_for_response(&bal_req_id, 10000).await?;
    let block_height = bal_resp
        .result
        .as_ref()
        .and_then(|r| r["block_height"].as_u64())
        .unwrap_or(0) as u32;
    if block_height == 0 {
        return Err("Could not determine block height".into());
    }
    let timeout = block_height + 288;

    // Operator's per-transfer fee matches the default schedule stored on the
    // deposit at make_offer time. Advertisements don't always carry it, so
    // compute it the same way `send` does.
    let operator_fee = {
        let default = deposits_core::types::TransferFeeSchedule::default();
        default
            .fixed_msats
            .saturating_add(amount_msats.saturating_mul(default.rate_bps as u64) / 10_000)
    };

    let completion_script = format!("sha256({})", hash_hex);
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let msg_hash = transfer_lock_signing_message(
        &nonce,
        &from_deposit_id,
        &dest_id,
        amount_msats,
        operator_fee,
        &completion_script,
        timeout,
    );
    let transfer_id = compute_transfer_id(&msg_hash);
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &from_keypair);

    let lock_params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(from_deposit_id),
        "destination_deposit_id": courier_deposit_id_hex,
        "amount": amount_msats,
        "fee": operator_fee,
        "completion_script": completion_script,
        "timeout_height": timeout,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

    let lock_req_id = transport
        .send_ledger_request(from_ledger, "transfer_lock", lock_params)
        .await?;
    let lock_resp = transport.wait_for_response(&lock_req_id, 30000).await?;
    if !lock_resp.success {
        return Err(format!("Lock failed: {}", lock_resp.error.unwrap_or_default()).into());
    }
    println!(
        "  Locked! Transfer ID: {}...",
        hex::encode(&transfer_id[..8])
    );
    println!();

    // Step 4: Wait for courier to forward on destination ledger
    println!("Waiting for courier to forward...");
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(90);
    let mut outbound_transfer_id = None;

    while tokio::time::Instant::now() < deadline {
        // Fetch recent TransferLock updates on the destination ledger
        let updates = transport.fetch_ledger_updates(to_ledger).await?;
        for update in &updates {
            use deposits_core::{LedgerOperation, TlvDecode};
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::TransferLock {
                    destination_deposit_id,
                    completion_script: ref script,
                    transfer_id: ref tid,
                    ..
                } = op
                {
                    if destination_deposit_id == to_deposit_id && script.contains(&hash_hex) {
                        outbound_transfer_id = Some(*tid);
                        break;
                    }
                }
            }
        }
        if outbound_transfer_id.is_some() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        eprint!(".");
    }
    eprintln!();

    let outbound_tid = outbound_transfer_id.ok_or("Courier did not forward within 90 seconds")?;
    println!(
        "  Courier forwarded! Outbound ID: {}...",
        hex::encode(&outbound_tid[..8])
    );
    println!();

    // Step 5: Complete by revealing preimage
    println!("Revealing preimage...");
    let complete_params = serde_json::json!({
        "transfer_id": hex::encode(outbound_tid),
        "preimage": hex::encode(preimage),
    });
    let complete_req_id = transport
        .send_ledger_request(to_ledger, "transfer_complete", complete_params)
        .await?;
    let complete_resp = transport.wait_for_response(&complete_req_id, 15000).await?;
    if !complete_resp.success {
        return Err(format!(
            "Complete failed: {}",
            complete_resp.error.unwrap_or_default()
        )
        .into());
    }

    println!();
    println!("Routed transfer complete!");
    println!(
        "  {} sats sent from {} to {} via courier",
        amount_sats, from_alias, to_alias
    );
    println!("  Fee: {} msats ({} sats)", route_fee, route_fee / 1000);
    Ok(())
}

/// Spread funds across multiple operators by opening deposits
///
/// Usage: deposits-wallet spread <amount_sats> [--count N] --relay <url> [--relay <url>...]
pub async fn spread_deposits(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut amount_sats: Option<u64> = None;
    let mut count: usize = 0; // 0 = all discovered operators
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" if i + 1 < args.len() => {
                count = args[i + 1].parse()?;
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let total_sats = amount_sats
        .ok_or("Usage: deposits-wallet spread <amount_sats> [--count N] --relay <url>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    // Discover operators
    println!("Discovering operators...");
    let nostr_key = config.nostr_key()?;
    let mut transport = NostrTransportBuilder::new(nostr_key);
    for r in &config.relays {
        transport = transport.relay(r);
    }
    let transport = transport.build().await?;

    let ads = transport.fetch_ledger_advertisements(network_str).await?;
    if ads.is_empty() {
        return Err("No operators found. Check relay connectivity.".into());
    }

    // Deduplicate by operator pubkey — one ledger per operator
    let mut seen_operators = std::collections::HashSet::new();
    let mut targets = Vec::new();
    for ad in &ads {
        if seen_operators.insert(ad.operator_pubkey.clone()) {
            targets.push(ad);
        }
    }

    if count > 0 && count < targets.len() {
        targets.truncate(count);
    }

    let n = targets.len();
    let per_deposit = total_sats / n as u64;
    let remainder = total_sats % n as u64;

    println!("  Found {} operators", n);
    println!(
        "  Spreading {} sats across {} deposits ({} sats each)",
        total_sats, n, per_deposit
    );
    println!();

    // Load existing deposits to avoid duplicates and generate aliases
    let deposits_file = config.data_dir.join("deposits.json");
    let existing: Vec<serde_json::Value> = if deposits_file.exists() {
        serde_json::from_str(&std::fs::read_to_string(&deposits_file)?)?
    } else {
        Vec::new()
    };

    let existing_ledgers: std::collections::HashSet<String> = existing
        .iter()
        .filter_map(|d| {
            d.get("ledger_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let mut opened = 0;
    let mut skipped = 0;

    for (idx, ad) in targets.iter().enumerate() {
        let name = ad.operator_name.as_deref().unwrap_or("unknown");
        let ledger_id = &ad.ledger_id;

        if existing_ledgers.contains(ledger_id) {
            println!(
                "  {} ({}...): already have deposit, skipping",
                name,
                &ledger_id[..8]
            );
            skipped += 1;
            continue;
        }

        let deposit_amount = if idx == 0 {
            per_deposit + remainder
        } else {
            per_deposit
        };
        let alias = format!("{}-{}", name.to_lowercase(), &ledger_id[..4]);

        println!(
            "  {} ({}...): opening {} sats as '{}'...",
            name,
            &ledger_id[..8],
            deposit_amount,
            alias
        );

        // Shared config args — operator's relay first (where they
        // listen for requests), then user's relays as fallback.
        let mut shared_args: Vec<String> = Vec::new();
        if let Some(ref relay_url) = ad.relay_url {
            shared_args.push("--relay".to_string());
            shared_args.push(relay_url.clone());
        }
        for r in &config.relays {
            if ad.relay_url.as_deref() != Some(r.as_str()) {
                shared_args.push("--relay".to_string());
                shared_args.push(r.clone());
            }
        }
        shared_args.push("--seed".to_string());
        shared_args.push(hex::encode(config.seed));
        shared_args.push("--network".to_string());
        shared_args.push(network_str.to_string());
        shared_args.push("--data-dir".to_string());
        shared_args.push(config.data_dir.to_string_lossy().to_string());

        // Step 1: create the empty deposit account.
        let mut open_args: Vec<String> = vec![
            ledger_id.clone(),
            "--alias".to_string(),
            alias.clone(),
        ];
        open_args.extend_from_slice(&shared_args);

        if let Err(e) = open_new_deposit(&open_args).await {
            eprintln!("    Failed to open: {}", e);
            continue;
        }

        // Step 2: request an on-chain funding address via make_offer.
        // Failures here leave the account created but unfunded —
        // recoverable with a manual `offer` command.
        let mut offer_args: Vec<String> = vec![alias, deposit_amount.to_string()];
        offer_args.extend_from_slice(&shared_args);

        if let Err(e) = add_offer(&offer_args).await {
            eprintln!("    Opened, but offer failed: {}", e);
            continue;
        }
        opened += 1;
    }

    println!();
    println!(
        "Spread complete: {} opened, {} skipped (existing)",
        opened, skipped
    );
    if opened > 0 {
        println!();
        println!("Fund the deposits with on-chain transactions or 'offer' commands.");
        println!("Use 'list' to see deposit addresses and 'sync' to update balances.");
    }
    Ok(())
}

/// Create a Lightning invoice for a deposit
/// The operator's LDK sidecar creates the invoice, payment credits the deposit
pub async fn make_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut description: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--description" | "-d" if i + 1 < args.len() => {
                description = Some(args[i + 1].clone());
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias =
        alias.ok_or("Usage: deposits-wallet make_invoice <alias> <amount_sats> --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| {
            format!(
                "No deposit found with alias '{}'. Use 'list' to see your deposits.",
                alias
            )
        })?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    let (descriptor, _deposit_id_hex) = deposit_record_identity(deposit)
        .ok_or("Deposit record missing descriptor / deposit_pubkey — re-open this deposit")?;

    // Use nostr identity key for transport
    let nostr_key = config.nostr_key()?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "descriptor": descriptor,
        "amount_sats": amount_sats,
        "description": description.unwrap_or_else(|| format!("Deposit to {}", alias)),
    });

    println!("Requesting Lightning invoice...");
    println!("  Alias: {}", alias);
    println!("  Amount: {} sats", amount_sats);

    let request_id = transport
        .send_ledger_request(ledger_id, "make_invoice", request_params)
        .await?;

    // Wait for response using real-time subscription
    match transport.wait_for_response(&request_id, 60000).await {
        Ok(response) => {
            if response.success {
                if let Some(result) = &response.result {
                    if let Some(invoice) = result.get("invoice").and_then(|v| v.as_str()) {
                        println!();
                        println!("{}", invoice);
                        return Ok(());
                    }
                }
                Err("Response missing invoice".into())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Invoice request failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for operator response: {}", e).into()),
    }
}

/// Pay a Lightning invoice from a deposit
/// The operator's LDK sidecar pays the invoice, debiting the deposit
pub async fn pay_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut invoice: Option<String> = None;
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
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if invoice.is_none() {
                    invoice = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or("Usage: deposits-wallet pay_invoice <alias> <bolt11> --relay <url>")?;
    let invoice = invoice.ok_or("Missing bolt11 invoice")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| {
            format!(
                "No deposit found with alias '{}'. Use 'list' to see your deposits.",
                alias
            )
        })?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    // Get key for signing
    let key_index = deposit
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);

    // Use nostr identity key for transport
    let nostr_key = config.nostr_key()?;

    // Parse the bolt11 invoice to extract payment_hash and amount
    use lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;

    let parsed_invoice = Bolt11Invoice::from_str(&invoice)
        .map_err(|e| format!("Invalid bolt11 invoice: {:?}", e))?;

    let payment_hash = parsed_invoice.payment_hash();
    let mut payment_hash_bytes = [0u8; 32];
    payment_hash_bytes.copy_from_slice(payment_hash.as_ref());

    let amount_msats = parsed_invoice
        .amount_milli_satoshis()
        .ok_or("Invoice has no amount")?;

    // Source descriptor of truth from the deposit record.
    let (descriptor, deposit_id_hex) = deposit_record_identity(deposit)
        .ok_or("Deposit record missing descriptor / deposit_pubkey — re-open this deposit")?;
    let deposit_id_bytes =
        hex::decode(&deposit_id_hex).map_err(|e| format!("Bad stored deposit_id: {}", e))?;
    let mut deposit_id = [0u8; 16];
    deposit_id.copy_from_slice(&deposit_id_bytes);

    // Sign the INVOICE message (deposit_id, payment_hash, amount). The
    // witness is whatever satisfies the descriptor — for pk(...) it's
    // a single Schnorr sig on the message hash.
    let msg_hash = deposits_core::signature_utils::invoice_lock_signing_message(
        &deposit_id,
        &payment_hash_bytes,
        amount_msats,
    );
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.serialize().to_vec()],
    };

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "descriptor": descriptor,
        "invoice": invoice,
        "payment_hash": hex::encode(payment_hash_bytes),
        "amount_msats": amount_msats,
        "witness": witness,
    });

    println!("Paying Lightning invoice...");
    println!("  Alias: {}", alias);
    println!("  Invoice: {}...", &invoice[..40.min(invoice.len())]);
    println!("  Amount: {} msats", amount_msats);

    let request_id = transport
        .send_ledger_request(ledger_id, "pay_invoice", request_params)
        .await?;

    // Wait for response using real-time subscription (longer timeout for LN payments)
    match transport.wait_for_response(&request_id, 120000).await {
        Ok(response) => {
            if response.success {
                println!();
                println!("Payment successful!");
                if let Some(result) = &response.result {
                    if let Some(preimage) = result.get("preimage").and_then(|v| v.as_str()) {
                        println!("  Preimage: {}", preimage);
                    }
                }
                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Payment failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for payment confirmation: {}", e).into()),
    }
}

/// Show transaction history for a deposit
pub async fn show_history(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut config_args = Vec::new();

    for arg in args {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
        } else if alias.is_none() {
            alias = Some(arg.clone());
        }
    }

    let alias = alias.ok_or("Usage: deposits-wallet history <alias> --relay <url>")?;
    let config = parse_config(&config_args)?;

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| {
            format!(
                "No deposit found with alias '{}'. Use 'list' to see your deposits.",
                alias
            )
        })?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    println!("Transaction History: {}", alias);
    println!("====================");
    println!();
    println!("  Ledger: {}", ledger_id);
    println!();
    println!("(History implementation pending - use deposits-node for now)");

    Ok(())
}

/// Happy-path intra-ledger transfer: synthesize preimage, lock, and immediately complete.
///
/// Usage: deposits-wallet send <src_alias> <amount_sats> --to <dst> --relay <url>
///
/// `<dst>` accepts: local alias, 32-char hex deposit_id, or hex prefix.
/// Timeout is derived from the operator's advertised chain tip (no extra round-trip).
pub async fn send(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    use deposits_core::signature_utils::{compute_transfer_id, transfer_lock_signing_message};
    use deposits_core::types::compute_deposit_id;

    let mut src_alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut dst_arg: Option<String> = None;
    let mut timeout_blocks: u32 = 500; // safely under default max 1008
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" if i + 1 < args.len() => {
                dst_arg = Some(args[i + 1].clone());
                i += 1;
            }
            "--timeout-blocks" if i + 1 < args.len() => {
                timeout_blocks = args[i + 1].parse()?;
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if src_alias.is_none() {
                    src_alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let src_alias = src_alias
        .ok_or("Usage: deposits-wallet send <src_alias> <amount_sats> --to <dst> --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let dst_arg = dst_arg.ok_or("Missing destination. Use --to <alias|deposit_id>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }
    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let src = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&src_alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'", src_alias))?;

    let ledger_id = src
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?
        .to_string();

    // Resolve destination: alias, full hex (32 chars), or hex prefix.
    let dest_id: [u8; 16] = {
        if let Some(dest_dep) = deposits
            .iter()
            .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&dst_arg))
        {
            // Local alias — compute deposit_id from descriptor.
            let key_index = dest_dep
                .get("key_index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let sk = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
            let secp = Secp256k1::new();
            let pk = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk).public_key();
            let descriptor = format!("pk({})", hex::encode(pk.serialize()));
            compute_deposit_id(&descriptor)
        } else {
            // Treat as hex. Accept 32 chars (full) or shorter prefix to match a stored deposit_id.
            let lower = dst_arg.to_lowercase();
            let bytes = hex::decode(&lower)
                .map_err(|_| format!("Destination '{}' is not a known alias or hex", dst_arg))?;
            if bytes.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                id
            } else {
                return Err(format!(
                    "Destination deposit_id must be exactly 32 hex chars (got {})",
                    lower.len()
                )
                .into());
            }
        }
    };

    // Fetch the ledger advertisement for the source ledger to pick a safe timeout.
    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;
    transport.set_response_ledger_filter(vec![ledger_id.clone()]);

    let ad = transport
        .fetch_ledger_advertisement(&ledger_id)
        .await?
        .ok_or_else(|| format!("No advertisement for ledger {}", &ledger_id[..16]))?;

    if ad.current_block == 0 {
        return Err("Operator did not advertise a chain tip; cannot pick timeout.".into());
    }
    let timeout_height = ad.current_block + timeout_blocks;

    // Synthesize preimage and hash.
    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let hash = sha256::Hash::hash(&preimage);
    let hash_hex = hex::encode(hash.as_byte_array());
    let completion_script = format!("sha256({})", hash_hex);

    // Source keypair.
    let src_key_index = src
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let src_sk = derive_secret_key_at_index(&config.seed, config.network, src_key_index)?;
    let secp = Secp256k1::new();
    let src_kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &src_sk);
    let src_pk = src_kp.public_key();
    let src_descriptor = format!("pk({})", hex::encode(src_pk.serialize()));
    let source_id = compute_deposit_id(&src_descriptor);

    let amount_msats = amount_sats * 1000;

    // Auto-fee from default schedule.
    let fee_msats = {
        let default = deposits_core::types::TransferFeeSchedule::default();
        default
            .fixed_msats
            .saturating_add(amount_msats.saturating_mul(default.rate_bps as u64) / 10_000)
    };

    // Nonce + transfer_id signature.
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let msg_hash = transfer_lock_signing_message(
        &nonce,
        &source_id,
        &dest_id,
        amount_msats,
        fee_msats,
        &completion_script,
        timeout_height,
    );
    let transfer_id = compute_transfer_id(&msg_hash);
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &src_kp);

    println!("Send");
    println!("====");
    println!("  From:     {} ({})", src_alias, hex::encode(&source_id[..4]));
    println!("  To:       {}", hex::encode(dest_id));
    println!("  Amount:   {} sats", amount_sats);
    println!("  Fee:      {} msats", fee_msats);
    println!("  Tip:      block {}", ad.current_block);
    println!("  Timeout:  block {} (+{} blocks)", timeout_height, timeout_blocks);
    println!("  Transfer: {}", hex::encode(transfer_id));
    println!();

    // ─── Phase 1: lock ───
    let lock_params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(source_id),
        "destination_deposit_id": hex::encode(dest_id),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

    println!("[1/2] Locking funds...");
    let lock_req_id = transport
        .send_ledger_request(&ledger_id, "transfer_lock", lock_params)
        .await?;
    let lock_resp = transport
        .wait_for_response(&lock_req_id, 10_000)
        .await
        .map_err(|e| format!("Timeout waiting for lock response: {}", e))?;
    if !lock_resp.success {
        let err = lock_resp.error.as_deref().unwrap_or("unknown");
        return Err(format!("transfer_lock rejected: {}", err).into());
    }
    println!("      locked");

    // ─── Phase 2: reveal preimage ───
    let complete_params = serde_json::json!({
        "transfer_id": hex::encode(transfer_id),
        "preimage": hex::encode(preimage),
    });

    println!("[2/2] Revealing preimage...");
    let complete_req_id = transport
        .send_ledger_request(&ledger_id, "transfer_complete", complete_params)
        .await?;
    let complete_resp = transport
        .wait_for_response(&complete_req_id, 10_000)
        .await
        .map_err(|e| format!("Timeout waiting for complete response: {}", e))?;
    if !complete_resp.success {
        let err = complete_resp.error.as_deref().unwrap_or("unknown");
        return Err(format!("transfer_complete rejected: {}", err).into());
    }
    println!("      completed");
    println!();
    println!("Sent {} sats.", amount_sats);

    Ok(())
}
