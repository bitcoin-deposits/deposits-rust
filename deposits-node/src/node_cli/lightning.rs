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

/// Handle lightning (ln) subcommands
pub async fn lightning_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning <command> [args...]");
        eprintln!("\nLDK Sidecar Commands (via ldk-server-cli):");
        eprintln!("  invoice <amount_sats> [description]  Create a Lightning invoice");
        eprintln!("  pay <bolt11_invoice>                 Pay a Lightning invoice");
        eprintln!("  balance                              Show Lightning wallet balance");
        eprintln!("  info                                 Show LDK node info");
        eprintln!("  channels                             List Lightning channels");
        eprintln!("  payments                             List payments");
        eprintln!(
            "  locks    [ledger_id]                  Show open invoice locks awaiting completion"
        );
        eprintln!("\nDeposit Payment Commands:");
        eprintln!("  send     Pay invoice FROM a deposit (lock, pay, fulfill in one step)");
        eprintln!("\nLedger Operation Commands:");
        eprintln!("  lock     Lock deposit funds for an outgoing Lightning payment");
        eprintln!("  fail     Fail/cancel a pending Lightning payment and unlock funds");
        eprintln!("  fulfill  Complete a Lightning payment with the preimage");
        return Ok(());
    }

    match args[0].as_str() {
        // LDK sidecar commands
        "invoice" => lightning_invoice(&args[1..]).await,
        "pay" => lightning_pay(&args[1..]).await,
        "balance" => lightning_balance(&args[1..]).await,
        "info" => lightning_info(&args[1..]).await,
        "channels" => lightning_channels(&args[1..]).await,
        "payments" => lightning_payments(&args[1..]).await,
        "locks" => lightning_open_locks(&args[1..]).await,
        // Ledger operation commands
        "lock" => lightning_lock(&args[1..]).await,
        "fail" => lightning_fail(&args[1..]).await,
        "fulfill" => lightning_fulfill(&args[1..]).await,
        // Combined commands
        "send" => lightning_send(&args[1..]).await,
        cmd => {
            eprintln!("Unknown lightning subcommand: {}", cmd);
            eprintln!("Usage: deposits-node lightning <invoice|pay|balance|info|channels|send|lock|fail|fulfill> [args...]");
            Ok(())
        }
    }
}

async fn lightning_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning invoice <amount_sats> [description]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning invoice 50000 \"Payment for service\"");
        return Ok(());
    }

    let amount_sats: u64 = args[0]
        .parse()
        .map_err(|_| format!("Invalid amount: {}", args[0]))?;
    let amount_msat = amount_sats * 1000;
    let description = args.get(1).map(|s| s.as_str()).unwrap_or("Deposit invoice");

    let cli = LdkCli::from_env();
    let invoice = cli.create_invoice(amount_msat, description)?;

    println!("{}", invoice);
    Ok(())
}

async fn lightning_pay(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning pay <bolt11_invoice>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning pay lnbc50u1p...");
        return Ok(());
    }

    let invoice = &args[0];

    let cli = LdkCli::from_env();
    let payment_id = cli.pay_invoice(invoice)?;

    println!("Payment initiated!");
    println!("  Payment ID: {}", payment_id);
    Ok(())
}

async fn lightning_balance(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let balances = cli.get_balances()?;

    println!("Lightning Wallet Balance:");
    println!(
        "  On-chain total:     {} sats",
        balances.total_onchain_balance_sats
    );
    println!(
        "  On-chain spendable: {} sats",
        balances.spendable_onchain_balance_sats
    );
    println!(
        "  Lightning balance:  {} sats",
        balances.total_lightning_balance_sats
    );
    println!(
        "  Anchor reserves:    {} sats",
        balances.total_anchor_channels_reserve_sats
    );
    Ok(())
}

async fn lightning_info(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let info = cli.get_node_info()?;

    println!("LDK Node Info:");
    println!("  Node ID: {}", info.node_id);
    if let Some(block) = info.current_best_block {
        println!("  Block height: {}", block.height);
        println!("  Block hash: {}", block.block_hash);
    }
    Ok(())
}

async fn lightning_channels(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let response = cli.list_channels()?;

    if response.channels.is_empty() {
        println!("No channels found.");
        return Ok(());
    }

    println!("Lightning Channels ({} total):", response.channels.len());
    println!();

    for channel in response.channels {
        let status = if channel.is_usable {
            "usable"
        } else if channel.is_channel_ready {
            "ready"
        } else {
            "pending"
        };

        println!("  Channel: {}...", &channel.channel_id[..16]);
        println!(
            "    Counterparty: {}...",
            &channel.counterparty_node_id[..16]
        );
        println!("    Capacity:  {} sats", channel.channel_value_sats);
        println!("    Outbound:  {} msat", channel.outbound_capacity_msat);
        println!("    Inbound:   {} msat", channel.inbound_capacity_msat);
        println!("    Status:    {}", status);
        println!();
    }
    Ok(())
}

async fn lightning_payments(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let response = cli.list_payments()?;

    if response.payments.is_empty() {
        println!("No payments found.");
        return Ok(());
    }

    println!("Lightning Payments ({} total):", response.payments.len());
    println!();

    for payment in response.payments {
        let status = match payment.status {
            0 => "pending",
            1 => "succeeded",
            2 => "failed",
            _ => "unknown",
        };

        println!("  Payment: {}...", &payment.id[..16.min(payment.id.len())]);
        if let Some(amount) = payment.amount_msat {
            println!("    Amount: {} msat ({} sats)", amount, amount / 1000);
        }
        println!("    Status: {}", status);
        println!();
    }
    Ok(())
}

async fn lightning_open_locks(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;
    let ledgers = node.handler.ledgers.lock().unwrap();

    let mut total = 0;
    for (lid, arc) in ledgers.iter() {
        let ledger = arc.read().unwrap();
        if ledger.state.open_invoice_locks.is_empty() {
            continue;
        }
        println!("Ledger {}...:", &lid[..16.min(lid.len())]);
        for (payment_id, lock) in &ledger.state.open_invoice_locks {
            println!("  Payment: {}", hex::encode(payment_id));
            println!("    Deposit: {}", hex::encode(lock.deposit_id));
            println!(
                "    Amount:  {} msat ({} sats)",
                lock.amount,
                lock.amount / 1000
            );
            println!("    Locked at seq: {}", lock.lock_sequence);
            println!();
            total += 1;
        }
    }

    if total == 0 {
        println!("No open invoice locks.");
    } else {
        println!("{} open lock(s) total.", total);

        // If LDK is available, show payment status for each
        use crate::ldk_cli::LdkCli;
        let cli = LdkCli::from_env();
        if let Ok(resp) = cli.list_payments() {
            println!("\nLDK payment status:");
            for (lid, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();
                for payment_id in ledger.state.open_invoice_locks.keys() {
                    let hex_id = hex::encode(payment_id);
                    let matching = resp.payments.iter().find(|p| p.id == hex_id);
                    let status = match matching {
                        Some(p) => match p.status {
                            0 => "PENDING",
                            1 => "SUCCEEDED (needs fulfill)",
                            2 => "FAILED (needs fail)",
                            _ => "UNKNOWN",
                        },
                        None => "NOT FOUND in LDK",
                    };
                    println!(
                        "  {}... on {}...: {}",
                        &hex_id[..16],
                        &lid[..16.min(lid.len())],
                        status
                    );
                }
            }
        }
    }

    Ok(())
}

async fn lightning_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    if positional.len() < 7 {
        eprintln!(
            "Usage: deposits-node lightning lock \
             <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <signature> \
             <op_nonce> <op_expiry>"
        );
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes =
        hex::decode(&positional[3]).map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    let signature_bytes =
        hex::decode(&positional[4]).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if signature_bytes.len() != 64 {
        return Err("Signature must be 64 bytes (128 hex characters)".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);

    // dep-17 replay-protection fields: the signature above is over the
    // operation preimage that includes these. Caller produced it externally
    // (sign_op + the exact same nonce/expiry).
    let op_nonce: u64 = positional[5]
        .parse()
        .map_err(|_| format!("Invalid op_nonce: {}", positional[5]))?;
    let op_expiry: u32 = positional[6]
        .parse()
        .map_err(|_| format!("Invalid op_expiry: {}", positional[6]))?;

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Locking deposit for Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!(
        "  Amount: {} msats ({} sats)",
        amount_msats,
        amount_msats / 1000
    );
    println!(
        "  Payment ID: {}",
        &positional[3][..16.min(positional[3].len())]
    );

    let new_locked = node
        .lock_invoice_payment(
            reserves_id,
            deposit_id,
            amount_msats,
            payment_id,
            op_nonce,
            op_expiry,
            witness,
        )
        .await?;

    println!("\nPayment locked!");
    println!(
        "  Locked balance: {} msats ({} sats)",
        new_locked,
        new_locked / 1000
    );

    Ok(())
}

async fn lightning_fail(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    if positional.len() < 4 {
        eprintln!("Usage: deposits-node lightning fail <reserves_id> <deposit_pubkey> <amount_msats> <payment_id>");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes =
        hex::decode(&positional[3]).map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    // Compute deposit_id from pubkey
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Failing Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!(
        "  Amount to unlock: {} msats ({} sats)",
        amount_msats,
        amount_msats / 1000
    );

    let new_balance = node
        .fail_invoice_payment(reserves_id, deposit_id, amount_msats, payment_id)
        .await?;

    println!("\nPayment failed/cancelled!");
    println!(
        "  New balance: {} msats ({} sats)",
        new_balance,
        new_balance / 1000
    );

    Ok(())
}

async fn lightning_fulfill(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    if positional.len() < 6 {
        eprintln!("Usage: deposits-node lightning fulfill <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <preimage> <signature>");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes =
        hex::decode(&positional[3]).map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    let preimage_bytes =
        hex::decode(&positional[4]).map_err(|e| format!("Invalid preimage hex: {}", e))?;
    if preimage_bytes.len() != 32 {
        return Err("Preimage must be 32 bytes (64 hex characters)".into());
    }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&preimage_bytes);

    let signature_bytes =
        hex::decode(&positional[5]).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if signature_bytes.len() != 64 {
        return Err("Signature must be 64 bytes (128 hex characters)".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Fulfilling Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!(
        "  Amount: {} msats ({} sats)",
        amount_msats,
        amount_msats / 1000
    );

    let new_balance = node
        .fulfill_invoice_payment(
            reserves_id,
            deposit_id,
            amount_msats,
            payment_id,
            preimage,
            witness,
        )
        .await?;

    println!("\nPayment fulfilled!");
    println!(
        "  New balance: {} msats ({} sats)",
        new_balance,
        new_balance / 1000
    );

    Ok(())
}

/// Send a Lightning payment FROM a deposit (combined lock + pay + fulfill)
async fn lightning_send(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;
    use crate::ldk_cli::LdkCli;

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

    if positional.len() < 3 {
        eprintln!("Usage: deposits-node lightning send <reserves_id> <deposit_secret_hex> <bolt11_invoice>");
        eprintln!("\nThis pays an invoice FROM a deposit by:");
        eprintln!("  1. Locking funds (InvoiceLock)");
        eprintln!("  2. Paying via Lightning (LDK sidecar)");
        eprintln!("  3. Fulfilling with preimage (InvoiceFulfill)");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let secret_hex = &positional[1];
    let invoice = &positional[2];

    // Parse secret key
    let secret_bytes = hex::decode(secret_hex).map_err(|e| format!("Invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err("Secret key must be 32 bytes".into());
    }
    let secret_key =
        SecretKey::from_slice(&secret_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Derive public key and compute deposit_id
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &secret_key);
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    let cli = LdkCli::from_env();

    println!("Sending Lightning payment from deposit...");
    println!("  Reserves: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Invoice: {}...", &invoice[..40.min(invoice.len())]);

    // Step 1: Pay the invoice via LDK to get payment_id and check success
    println!("\nStep 1: Paying invoice via Lightning...");
    let payment_id_hex = cli.pay_invoice(invoice)?;
    println!(
        "  Payment initiated: {}...",
        &payment_id_hex[..20.min(payment_id_hex.len())]
    );

    // Convert payment_id to bytes
    let payment_id_bytes =
        hex::decode(&payment_id_hex).map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err(format!("Payment ID unexpected length: {}", payment_id_bytes.len()).into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    // Wait for payment to complete
    println!("  Waiting for payment to settle...");
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Check payment status and get preimage
    let payments = cli.list_payments()?;
    let payment = payments
        .payments
        .iter()
        .find(|p| p.id == payment_id_hex)
        .ok_or("Payment not found in payment list")?;

    if payment.status != 1 {
        return Err(format!("Payment failed with status: {}", payment.status).into());
    }

    let preimage_hex = payment
        .preimage
        .as_ref()
        .ok_or("Payment succeeded but no preimage returned")?;
    let preimage_bytes =
        hex::decode(preimage_hex).map_err(|e| format!("Invalid preimage hex: {}", e))?;
    if preimage_bytes.len() != 32 {
        return Err("Preimage unexpected length".into());
    }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&preimage_bytes);

    let amount_msats = payment
        .amount_msat
        .ok_or("Payment succeeded but no amount returned")?;

    println!("  Payment succeeded!");
    println!("  Amount: {} msats", amount_msats);
    println!("  Preimage: {}...", &preimage_hex[..16]);

    // Step 2: Create signatures and record ledger operations
    println!("\nStep 2: Recording on ledger...");

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Sign the dep-17 operation preimage for InvoiceLock. The wallet would
    // normally do this; here the CLI has the private key directly. Pick a
    // fresh op_nonce and a sentinel op_expiry — same defaults the operator
    // used before this path was lifted into the wallet.
    let op_nonce = deposits_core::signing::fresh_op_nonce();
    let op_expiry = u32::MAX;
    let lock_proto = deposits_core::messages::LedgerOperation::InvoiceLock {
        deposit_id,
        amount: amount_msats,
        payment_id,
        sequence_number: 0,
        nonce: op_nonce,
        expiry: op_expiry,
        witness: deposits_core::types::DescriptorWitness::new(),
    };
    let lock_signed = deposits_core::signing::sign_op(lock_proto, &secret_key)
        .ok_or("sign_op failed: unsignable variant")?;
    let lock_witness = match &lock_signed {
        deposits_core::messages::LedgerOperation::InvoiceLock { witness, .. } => witness.clone(),
        _ => unreachable!("sign_op preserves variant"),
    };
    // Fulfill carries its own witness — same signature shape as lock since
    // the descriptor evaluates against the same preimage.
    let fulfill_witness = lock_witness.clone();

    // Lock the funds with co-signing
    println!("  Locking {} msats...", amount_msats);
    let locked_balance = node
        .lock_invoice_payment(
            reserves_id,
            deposit_id,
            amount_msats,
            payment_id,
            op_nonce,
            op_expiry,
            lock_witness,
        )
        .await?;
    println!("  Locked balance: {} msats", locked_balance);

    // Fulfill with preimage and co-signing
    println!("  Fulfilling with preimage...");
    let new_balance = node
        .fulfill_invoice_payment(
            reserves_id,
            deposit_id,
            amount_msats,
            payment_id,
            preimage,
            fulfill_witness,
        )
        .await?;

    println!("\nPayment complete!");
    println!(
        "  Paid: {} msats ({} sats)",
        amount_msats,
        amount_msats / 1000
    );
    println!(
        "  New balance: {} msats ({} sats)",
        new_balance,
        new_balance / 1000
    );

    Ok(())
}
