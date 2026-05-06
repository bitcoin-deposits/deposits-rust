// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::parse_config;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use crate::Node;

/// Handle reserves subcommands
pub async fn reserves_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() || args[0].starts_with("--") {
        eprintln!(
            "Usage: deposits-node reserves <list|spend> [args...]\n\
             \n\
             Subcommands:\n\
               list    List the operator's Taproot reserves UTXOs\n\
               spend   Emergency-spend a Taproot reserves UTXO using quorum keys"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" => reserves_list(&args[1..]).await,
        "spend" => reserves_spend(&args[1..]).await,
        cmd => {
            eprintln!("Unknown reserves subcommand: {}", cmd);
            eprintln!("Run `deposits-node reserves` for usage.");
            Ok(())
        }
    }
}

/// List Taproot reserves UTXOs across every per-ledger wallet on this
/// operator. Each ledger's vault has its own entry; the listing groups
/// by ledger id.
pub async fn reserves_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let ledger_wallets: Vec<_> = node
        .ledger_wallets
        .read()
        .unwrap()
        .iter()
        .map(|(id, w)| (id.clone(), w.clone()))
        .collect();

    let mut found_any = false;
    for (ledger_id, lw) in ledger_wallets {
        let info = match lw.taproot_reserves() {
            Some(i) => i,
            None => continue,
        };
        found_any = true;
        println!("=== Ledger {} ===", &ledger_id);
        println!("  Outpoint: {}", info.outpoint);
        println!("    Amount: {} sats", info.amount);
        println!("    Operator: {}", info.operator);
        println!("    Quorum Members: {}", info.quorum_members.len());
        for (i, member) in info.quorum_members.iter().enumerate() {
            println!("      {}: {}", i + 1, member);
        }
        println!("    First Expiry: block {}", info.quorum_expiry);
        println!("    Ledger Hash: {}", hex::encode(&info.ledger_hash[..8]));
        println!("    Confirmed: {}", info.confirmed);

        println!();
        println!("    === Taproot Script Details ===");
        println!("    Internal Key: {}", info.taproot_output.internal_key());
        if let Some(merkle_root) = info.taproot_output.merkle_root() {
            println!("    Merkle Root: {}", merkle_root);
        }
        println!(
            "    ScriptPubKey: {}",
            hex::encode(info.taproot_output.script_pubkey().as_bytes())
        );
        println!();
        println!("    === Spending Tiers (Script Leaves) ===");
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            println!(
                "    Tier {}: {} (threshold={}, tie_breaker={}, timelock={})",
                i,
                tier.description,
                tier.threshold,
                tier.requires_tie_breaker,
                tier.timelock_blocks
            );
            if let Some(cb) = info.taproot_output.control_block_for_tier(i) {
                println!("      Control Block: {}", hex::encode(cb.serialize()));
            }
        }
        println!();
        println!("    === Full Script Tree (for decoding) ===");
        let voter_set = deposits_core::VoterSet::new(info.operator, info.quorum_members.clone());
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            let builder = deposits_core::TapscriptReservesBuilder::new(
                voter_set.clone(),
                info.taproot_output.config.clone(),
                lw.network(),
                info.ledger_hash,
            );
            if let Ok(script) = builder.build_threshold_leaf(tier) {
                println!("    Leaf {}: {}", i, hex::encode(script.as_bytes()));
            }
        }
        println!();
    }

    if !found_any {
        println!("No reserves outputs found.");
    }
    Ok(())
}

/// Emergency spend: move reserves UTXO to a destination address using quorum keys.
///
/// Usage: reserves spend <destination_address> --key <hex_secret> [--key <hex_secret> ...] [--tier <N>] [--fee-rate <sat/vb>]
///
/// Requires enough keys to satisfy the chosen spending tier (default: tier 0 = majority of quorum).
/// The operator's key is required for tiers that include the operator (tie-breaker).
async fn reserves_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use deposits_core::tapscript_reserves::TapscriptReservesBuilder;

    let mut config_args = Vec::new();
    let mut destination: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();
    let mut seed_dir: Option<String> = None;
    let mut ledger_id_arg: Option<String> = None;
    let mut tier: usize = 0;
    let mut fee_rate: u64 = 2; // sat/vb default

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" if i + 1 < args.len() => {
                keys.push(args[i + 1].clone());
                i += 2;
            }
            "--seed-dir" if i + 1 < args.len() => {
                seed_dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--ledger" if i + 1 < args.len() => {
                ledger_id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--tier" if i + 1 < args.len() => {
                tier = args[i + 1].parse().map_err(|_| "Invalid --tier")?;
                i += 2;
            }
            "--fee-rate" if i + 1 < args.len() => {
                fee_rate = args[i + 1].parse().map_err(|_| "Invalid --fee-rate")?;
                i += 2;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
                i += 1;
            }
            _ => {
                if destination.is_none() {
                    destination = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    let destination = destination.ok_or(
        "Usage: reserves spend <dest_address> --ledger <ledger_id> --seed-dir <path> [--key <hex>] [--tier N] [--fee-rate N]"
    )?;

    if keys.is_empty() && seed_dir.is_none() {
        return Err("Provide --seed-dir <path> or at least one --key <hex>".into());
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;
    node.sync_wallet()?;

    let secp = Secp256k1::new();

    // Parse destination address
    let dest_addr = destination
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| format!("Invalid destination address: {}", e))?
        .require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;
    let dest_script = dest_addr.script_pubkey();

    // Collect secret keys from --key flags
    let mut secret_keys: Vec<SecretKey> = keys
        .iter()
        .map(|hex_str| {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid key hex: {}", e))?;
            SecretKey::from_slice(&bytes).map_err(|e| format!("Invalid secret key: {}", e))
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Auto-discover keys from --seed-dir: find all files named "seed", derive operator key
    if let Some(ref dir) = seed_dir {
        let seed_path = std::path::Path::new(dir);
        if !seed_path.is_dir() {
            return Err(format!("Seed directory not found: {}", dir).into());
        }
        fn find_seed_files(dir: &std::path::Path, results: &mut Vec<std::path::PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        find_seed_files(&path, results);
                    } else if path.file_name().and_then(|n| n.to_str()) == Some("seed") {
                        results.push(path);
                    }
                }
            }
        }
        let mut seed_files = Vec::new();
        find_seed_files(seed_path, &mut seed_files);

        for seed_file in &seed_files {
            let seed_hex = match std::fs::read_to_string(seed_file) {
                Ok(s) => s.trim().to_string(),
                Err(_) => continue,
            };
            if seed_hex.len() != 64 {
                continue;
            }
            if let Ok(seed_bytes) = hex::decode(&seed_hex) {
                if seed_bytes.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);
                    if let Ok(sk) = super::derive_operator_secret(&seed, config.network) {
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        let label = seed_file
                            .parent()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .unwrap_or("?");
                        println!(
                            "  Found seed: {} -> {}...",
                            label,
                            &hex::encode(pk.serialize())[..16]
                        );
                        secret_keys.push(sk);
                    }
                }
            }
        }
    }

    if secret_keys.is_empty() {
        return Err("No keys found. Provide --seed-dir or --key.".into());
    }

    // Locate the ledger's taproot reserves. Per-ledger storage means the
    // caller must say which ledger they're recovering — there's no
    // global "first reserves" anymore.
    let ledger_id = ledger_id_arg.ok_or(
        "Pass --ledger <id> to identify which ledger's reserves to spend (use `reserves list` to enumerate).",
    )?;
    let lw = node
        .ledger_wallet(&ledger_id)
        .ok_or_else(|| format!("No ledger wallet for {}", ledger_id))?;
    let reserves = lw
        .taproot_reserves()
        .ok_or_else(|| format!("Ledger {} has no taproot reserves", ledger_id))?;
    let outpoint = reserves.outpoint;
    let amount = reserves.amount;

    println!("Emergency Reserves Spend");
    println!("========================");
    println!("  Outpoint:    {}", outpoint);
    println!("  Amount:      {} sats", amount);
    println!("  Destination: {}", destination);
    println!(
        "  Tier:        {} ({})",
        tier,
        reserves
            .taproot_output
            .config
            .tiers
            .get(tier)
            .map(|t| t.description.as_str())
            .unwrap_or("?")
    );
    println!("  Fee rate:    {} sat/vb", fee_rate);
    println!("  Keys:        {}", keys.len());
    println!();

    // Get tier info
    let tier_info = reserves
        .taproot_output
        .config
        .tiers
        .get(tier)
        .ok_or(format!(
            "Tier {} does not exist (max: {})",
            tier,
            reserves.taproot_output.config.tiers.len() - 1
        ))?;

    // Build the leaf script for this tier
    let builder = TapscriptReservesBuilder::new(
        reserves.taproot_output.voter_set.clone(),
        reserves.taproot_output.config.clone(),
        config.network,
        reserves.ledger_hash,
    );
    let leaf_script = builder
        .build_threshold_leaf(tier_info)
        .map_err(|e| format!("Failed to build leaf script: {:?}", e))?;

    // Get control block
    let control_block = reserves
        .taproot_output
        .control_block_for_tier(tier)
        .ok_or("Failed to get control block for tier")?;

    // Build unsigned transaction
    let reserves_script_pubkey = reserves.taproot_output.script_pubkey();
    let params = deposits_core::tapscript_reserves::SpendTxParams {
        reserves_outpoint: outpoint,
        reserves_amount: amount,
        destination_script: dest_script.clone(),
        fee_rate_sat_vbyte: fee_rate,
    };
    let mut tx = deposits_core::tapscript_reserves::ReservesSpendBuilder::build_spend_transaction(
        &params,
        &reserves_script_pubkey,
    )?;

    // Compute sighash
    let sighash = deposits_core::tapscript_reserves::ReservesSpendBuilder::compute_sighash(
        &tx,
        0,
        amount,
        &reserves_script_pubkey,
        &leaf_script,
    )?;

    let sighash_bytes: &[u8] = sighash.as_ref();
    println!("  Sighash: {}", hex::encode(sighash_bytes));

    // Sign with each provided key
    // Get the voter set's sorted x-only pubkeys to know which slot each key fills
    let voter_pubkeys = reserves.taproot_output.voter_set.sorted_x_only_pubkeys();

    let mut signatures: Vec<Option<[u8; 64]>> = vec![None; voter_pubkeys.len()];
    let msg = Message::from_digest(*sighash.as_ref());

    for sk in &secret_keys {
        let keypair = Keypair::from_secret_key(&secp, sk);
        let xonly = keypair.x_only_public_key().0;

        if let Some(slot) = voter_pubkeys.iter().position(|pk| *pk == xonly) {
            let sig = secp.sign_schnorr(&msg, &keypair);
            signatures[slot] = Some(sig.serialize());
            println!(
                "  Signed slot {} ({}...)",
                slot,
                &hex::encode(xonly.serialize())[..16]
            );
        } else {
            eprintln!(
                "  WARNING: Key {}... is not in the voter set",
                &hex::encode(xonly.serialize())[..16]
            );
        }
    }

    let signed_count = signatures.iter().filter(|s| s.is_some()).count();
    println!(
        "\n  Signed: {}/{} required",
        signed_count, tier_info.threshold
    );

    if signed_count < tier_info.threshold {
        return Err(format!(
            "Not enough signatures: {} of {} required for tier {}",
            signed_count, tier_info.threshold, tier
        )
        .into());
    }

    // Build witness
    let witness =
        deposits_core::tapscript_reserves::ReservesSpendBuilder::create_checksigadd_witness(
            &signatures,
            &leaf_script,
            &control_block,
        );
    tx.input[0].witness = witness;

    // Serialize and display
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("\n  TxID:   {}", tx.compute_txid());
    println!("  Size:   {} vbytes", tx.vsize());
    println!("  Hex:    {}", &tx_hex[..80.min(tx_hex.len())]);
    println!("          (full hex: {} chars)", tx_hex.len());

    // Broadcast
    println!("\nBroadcasting...");
    match node.wallet.broadcast(&tx) {
        Ok(txid) => println!("  SUCCESS: Transaction broadcast (txid: {})", txid),
        Err(e) => {
            eprintln!("  Broadcast failed: {}", e);
            eprintln!("\n  Raw transaction (for manual broadcast):");
            println!("{}", tx_hex);
        }
    }

    Ok(())
}
