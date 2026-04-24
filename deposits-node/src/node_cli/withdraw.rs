// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::parse_config;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use crate::Node;
use std::str::FromStr;

/// Handle withdraw subcommands
pub async fn withdraw_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node withdraw <request|lock|complete|cancel|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "request" => withdraw_request(&args[1..]).await,
        "lock" => withdraw_lock(&args[1..]).await,
        "complete" => withdraw_complete(&args[1..]).await,
        "cancel" => withdraw_cancel(&args[1..]).await,
        "list" => withdraw_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown withdraw subcommand: {}", cmd);
            eprintln!(
                "Usage: deposits-node withdraw <request|lock|complete|cancel|list> [args...]"
            );
            Ok(())
        }
    }
}

/// Request a withdrawal (for depositors) - generates nonce and signature, then locks
async fn withdraw_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;

    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();
    let mut memo: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--memo" {
            i += 1;
            if i < args.len() {
                memo = Some(args[i].clone());
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 5 {
        eprintln!("Usage: deposits-node withdraw request <reserves_id> <deposit_secret_hex> <address> <amount_sats> <fee_sats> [--memo <text>] [options]");
        eprintln!(
            "\nThis command generates a nonce, signs the withdrawal request, and locks the funds."
        );
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    let secret_hex = &positional[1];
    let destination_address = positional[2].clone();
    let amount_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[3]))?;
    let fee_sats: u64 = positional[4]
        .parse()
        .map_err(|_| format!("Invalid fee_sats: {}", positional[4]))?;

    // Parse secret key
    let secret_bytes = hex::decode(secret_hex).map_err(|e| format!("Invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err("Secret key must be 32 bytes".into());
    }
    let secret_key =
        SecretKey::from_slice(&secret_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Derive public key
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    // Generate random nonce
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // Create signature
    let signature = deposits_core::create_withdrawal_signature(
        &secret_key,
        &nonce,
        &deposit_pubkey,
        &destination_address,
        amount_sats,
        fee_sats,
    )
    .map_err(|e| format!("Failed to create signature: {:?}", e))?;

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id =
        if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
            reserves_id_arg.clone()
        } else {
            node.get_ledger_with_id(reserves_id_arg)
                .map(|(lid, _)| lid)
                .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
        };

    // Sync wallet
    node.sync_wallet()?;

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let depositor_witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    println!("Requesting withdrawal...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal with co-signing
    let result = node
        .lock_withdrawal(
            &ledger_id,
            deposit_id,
            destination_address,
            amount_sats,
            fee_sats,
            nonce,
            depositor_witness,
            memo,
        )
        .await?;

    println!("\nWithdrawal locked!");
    println!(
        "  Withdrawal ID: {}",
        hex::encode(result.withdrawal.withdrawal_id)
    );
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!(
        "  Previous balance: {} msats",
        result.previous_balance_msats
    );
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!(
        "  deposits-node withdraw complete {} {}",
        ledger_id,
        hex::encode(result.withdrawal.withdrawal_id)
    );

    Ok(())
}

/// Lock funds for an on-chain withdrawal (operator-side, requires pre-signed request)
async fn withdraw_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();
    let mut memo: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--memo" {
            i += 1;
            if i < args.len() {
                memo = Some(args[i].clone());
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 7 {
        eprintln!("Usage: deposits-node withdraw lock <reserves_id> <deposit_pubkey> <address> <amount_sats> <fee_sats> <nonce_hex> <signature_hex> [--memo <text>] [options]");
        eprintln!("\nThe nonce and signature must be provided by the depositor.");
        eprintln!("For testing, use 'withdraw request' which handles signing automatically.");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    // Validate pubkey hex (used for descriptor creation below)
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let destination_address = positional[2].clone();
    let amount_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[3]))?;
    let fee_sats: u64 = positional[4]
        .parse()
        .map_err(|_| format!("Invalid fee_sats: {}", positional[4]))?;
    let nonce_hex = &positional[5];
    let signature_hex = &positional[6];

    // Parse nonce
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 32 {
        return Err("Nonce must be 32 bytes".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

    // Parse signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id =
        if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
            reserves_id_arg.clone()
        } else {
            node.get_ledger_with_id(reserves_id_arg)
                .map(|(lid, _)| lid)
                .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
        };

    // Sync wallet
    node.sync_wallet()?;

    println!("Locking withdrawal...");
    println!("  Ledger ID: {}", ledger_id);
    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let depositor_witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal with co-signing
    let result = node
        .lock_withdrawal(
            &ledger_id,
            deposit_id,
            destination_address,
            amount_sats,
            fee_sats,
            nonce,
            depositor_witness,
            memo,
        )
        .await?;

    println!("\nWithdrawal locked!");
    println!(
        "  Withdrawal ID: {}",
        hex::encode(result.withdrawal.withdrawal_id)
    );
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!(
        "  Previous balance: {} msats",
        result.previous_balance_msats
    );
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!(
        "  deposits-node withdraw complete {} {}",
        ledger_id,
        hex::encode(result.withdrawal.withdrawal_id)
    );

    Ok(())
}

/// Complete a withdrawal by broadcasting the transaction
async fn withdraw_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 2 {
        eprintln!("Usage: deposits-node withdraw complete <reserves_id> <withdrawal_id> [options]");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    let withdrawal_id_hex = &positional[1];
    let id_bytes =
        hex::decode(withdrawal_id_hex).map_err(|e| format!("Invalid withdrawal ID hex: {}", e))?;
    if id_bytes.len() != 32 {
        return Err("Withdrawal ID must be 32 bytes".into());
    }
    let mut withdrawal_id = [0u8; 32];
    withdrawal_id.copy_from_slice(&id_bytes);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id =
        if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
            reserves_id_arg.clone()
        } else {
            node.get_ledger_with_id(reserves_id_arg)
                .map(|(lid, _)| lid)
                .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
        };

    // Sync wallet
    node.sync_wallet()?;

    println!("Completing withdrawal {}...", &withdrawal_id_hex[..16]);

    let result = node.complete_withdrawal(&ledger_id, &withdrawal_id).await?;

    println!("\nWithdrawal completed!");
    println!("  Transaction ID: {}", result.txid);
    println!("  Amount: {} sats", result.amount_sats);
    println!("  Fee: {} sats", result.fee_sats);
    println!("  Final balance: {} msats", result.final_balance_msats);
    println!("\nThe transaction includes an OP_RETURN commitment proving");
    println!("this withdrawal was executed for the specific request.");

    Ok(())
}

/// Cancel a pending withdrawal
async fn withdraw_cancel(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut withdrawal_id_hex: Option<String> = None;
    let mut reason = "Cancelled by operator".to_string();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--reason" {
            i += 1;
            if i < args.len() {
                reason = args[i].clone();
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if withdrawal_id_hex.is_none() {
            withdrawal_id_hex = Some(args[i].clone());
        }
        i += 1;
    }

    let withdrawal_id_hex = withdrawal_id_hex.ok_or("Withdrawal ID required")?;
    let id_bytes =
        hex::decode(&withdrawal_id_hex).map_err(|e| format!("Invalid withdrawal ID hex: {}", e))?;
    if id_bytes.len() != 32 {
        return Err("Withdrawal ID must be 32 bytes".into());
    }
    let mut withdrawal_id = [0u8; 32];
    withdrawal_id.copy_from_slice(&id_bytes);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Cancelling withdrawal {}...", &withdrawal_id_hex[..16]);

    node.cancel_withdrawal(&withdrawal_id, reason)?;

    println!("Withdrawal cancelled!");
    println!("Funds have been unlocked and returned to the deposit.");

    Ok(())
}

/// List all withdrawals
async fn withdraw_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let withdrawals = node.list_withdrawals();

    if withdrawals.is_empty() {
        println!("No withdrawals found.");
        return Ok(());
    }

    println!("Withdrawals ({} total):", withdrawals.len());
    println!();

    for (withdrawal, status) in withdrawals {
        let status_str = match &status {
            deposits_core::OnChainWithdrawalStatus::Locked { locked_at_block } => {
                format!("Locked at block {}", locked_at_block)
            }
            deposits_core::OnChainWithdrawalStatus::Broadcast {
                txid,
                broadcast_at_block,
            } => {
                format!(
                    "Broadcast at block {} (txid: {})",
                    broadcast_at_block,
                    &txid[..16]
                )
            }
            deposits_core::OnChainWithdrawalStatus::Completed {
                txid,
                confirmed_at_block,
                confirmations,
            } => {
                format!(
                    "Completed at block {} ({} confs, txid: {})",
                    confirmed_at_block,
                    confirmations,
                    &txid[..16]
                )
            }
            deposits_core::OnChainWithdrawalStatus::Cancelled {
                cancelled_at_block,
                reason,
            } => {
                format!("Cancelled at block {}: {}", cancelled_at_block, reason)
            }
        };

        println!(
            "  Withdrawal: {}",
            hex::encode(&withdrawal.withdrawal_id[..8])
        );
        println!("    Status: {}", status_str);
        println!("    Deposit ID: {}", hex::encode(withdrawal.deposit_id));
        println!("    Destination: {}", withdrawal.destination_address);
        println!(
            "    Amount: {} sats + {} fee",
            withdrawal.amount_sats, withdrawal.fee_sats
        );
        if let Some(ref memo) = withdrawal.memo {
            println!("    Memo: {}", memo);
        }
        println!();
    }

    Ok(())
}
