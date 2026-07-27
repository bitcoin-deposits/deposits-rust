use bitcoin::secp256k1::Secp256k1;
use std::io::Write;

use super::{
    derive_secret_key, derive_secret_key_at_index, parse_config, NostrTransportBuilder,
    WalletConfig,
};

/// Deposit info cached in memory for batch mode
pub struct BatchDepositInfo {
    pub ledger_id: String,
    pub key_index: u32,
    pub keypair: bitcoin::secp256k1::Keypair,
    pub deposit_id: [u8; 16],
}

/// Load deposits from JSON file into a lookup map
fn load_batch_deposits(
    data_dir: &std::path::Path,
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<std::collections::HashMap<String, BatchDepositInfo>, Box<dyn std::error::Error>> {
    let deposits_file = data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    let secp = Secp256k1::new();

    let mut map = std::collections::HashMap::new();
    for d in &deposits {
        let alias = match d.get("alias").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => continue,
        };
        let ledger_id = match d.get("ledger_id").and_then(|v| v.as_str()) {
            Some(l) => l.to_string(),
            None => continue,
        };
        let key_index = d.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let secret_key = match derive_secret_key_at_index(seed, network, key_index) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let pubkey = keypair.public_key();
        let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

        map.insert(
            alias,
            BatchDepositInfo {
                ledger_id,
                key_index,
                keypair,
                deposit_id,
            },
        );
    }

    Ok(map)
}

/// Batch mode: persistent Nostr connection, JSON commands on stdin, JSON responses on stdout
pub async fn batch_mode(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Write};

    let config = parse_config(args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let nostr_key = config.nostr_key()?;
    let secp = Secp256k1::new();

    // Create persistent transport
    let mut transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Load deposits
    let mut deposits = load_batch_deposits(&config.data_dir, &config.seed, config.network)?;
    let mut last_reload = std::time::Instant::now();

    // Set response filter for relay-side #l tag filtering (reduces fan-out)
    {
        let ledger_ids: Vec<String> = deposits
            .values()
            .map(|d| d.ledger_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        if !ledger_ids.is_empty() {
            transport.set_response_ledger_filter(ledger_ids);
        }
    }

    // Signal ready
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, r#"{{"ready":true}}"#)?;
    out.flush()?;
    drop(out);

    // Read commands from stdin
    let stdin = std::io::stdin();
    let reader = stdin.lock();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let cmd: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let out = std::io::stdout();
                let mut out = out.lock();
                let _ = writeln!(
                    out,
                    r#"{{"id":null,"success":false,"error":"Invalid JSON: {}"}}"#,
                    e.to_string().replace('"', "'")
                );
                let _ = out.flush();
                continue;
            }
        };

        let id = cmd
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let action = cmd.get("cmd").and_then(|v| v.as_str()).unwrap_or("");

        // Reload deposits periodically
        if last_reload.elapsed() > std::time::Duration::from_secs(5) {
            if let Ok(new_deposits) =
                load_batch_deposits(&config.data_dir, &config.seed, config.network)
            {
                deposits = new_deposits;
            }
            last_reload = std::time::Instant::now();
        }

        // Check if transfer_lock references an unknown alias — reload and retry
        let needs_alias_reload = if action == "transfer_lock" {
            if let Some(alias) = cmd.get("alias").and_then(|v| v.as_str()) {
                !deposits.contains_key(alias)
            } else {
                false
            }
        } else {
            false
        };
        if needs_alias_reload {
            if let Ok(new_deposits) =
                load_batch_deposits(&config.data_dir, &config.seed, config.network)
            {
                deposits = new_deposits;
            }
            last_reload = std::time::Instant::now();
        }

        let response = match action {
            "transfer_lock" => {
                batch_transfer_lock(&cmd, &deposits, &mut transport, &secp, &config).await
            }
            "transfer_complete" => batch_transfer_complete(&cmd, &mut transport, &config).await,
            _ => {
                serde_json::json!({"success": false, "error": format!("Unknown command: {}", action)})
            }
        };

        // Merge id into response
        let mut resp = response;
        resp.as_object_mut()
            .map(|m| m.insert("id".to_string(), serde_json::Value::String(id)));

        let out = std::io::stdout();
        let mut out = out.lock();
        let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap_or_default());
        let _ = out.flush();
    }

    transport.disconnect().await;
    Ok(())
}

async fn batch_transfer_lock(
    cmd: &serde_json::Value,
    deposits: &std::collections::HashMap<String, BatchDepositInfo>,
    transport: &mut deposits_nostr::NostrTransport,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    _config: &WalletConfig,
) -> serde_json::Value {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    // Parse fields
    let alias = match cmd.get("alias").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return serde_json::json!({"success": false, "error": "Missing alias"}),
    };
    let amount_sats = match cmd.get("amount").and_then(|v| v.as_u64()) {
        Some(a) => a,
        None => return serde_json::json!({"success": false, "error": "Missing amount"}),
    };
    let dest_hex = match cmd.get("to").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => {
            return serde_json::json!({"success": false, "error": "Missing 'to' (destination deposit_id)"})
        }
    };
    let hash_hex = match cmd.get("hash").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"success": false, "error": "Missing hash"}),
    };
    let timeout_height = match cmd.get("timeout").and_then(|v| v.as_u64()) {
        Some(t) => t as u32,
        None => return serde_json::json!({"success": false, "error": "Missing timeout"}),
    };
    let fee_msats = cmd.get("fee").and_then(|v| v.as_u64()).unwrap_or(2);

    // Look up deposit
    let info = match deposits.get(alias) {
        Some(i) => i,
        None => {
            return serde_json::json!({"success": false, "error": format!("Unknown alias: {}", alias)})
        }
    };

    // Parse destination
    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return serde_json::json!({"success": false, "error": "Invalid destination deposit_id"})
        }
    };

    let completion_script = format!("sha256({})", hash_hex);

    // Convert to msats
    let amount_msats = amount_sats * 1000;

    // Wallet picks transfer_nonce (channel id), transfer_id (app id), and the
    // dep-17 replay nonce/expiry. sign_op binds the op preimage with these.
    let mut rng = OsRng;
    let mut transfer_nonce = [0u8; 32];
    rng.fill_bytes(&mut transfer_nonce);
    let mut transfer_id = [0u8; 32];
    rng.fill_bytes(&mut transfer_id);

    let op_nonce = deposits_core::signing::fresh_op_nonce();
    let op_expiry = u32::MAX; // TODO: tighter window via chain_tip + margin
    let proto = deposits_core::messages::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: info.deposit_id,
        destination_deposit_id: dest_bytes,
        amount: amount_msats,
        fee: fee_msats,
        completion_script: completion_script.clone(),
        timeout_height,
        transfer_id,
        nonce: op_nonce,
        expiry: op_expiry,
        witness: deposits_core::types::DescriptorWitness::new(),
        commitment: None,
    };
    let signed = match deposits_core::signing::sign_op(proto, &info.keypair.secret_key()) {
        Some(s) => s,
        None => return serde_json::json!({"success": false, "error": "sign_op failed"}),
    };
    let signature_bytes = match &signed {
        deposits_core::messages::LedgerOperation::TransferLock { witness, .. } => {
            witness.stack[0].clone()
        }
        _ => unreachable!("sign_op preserves variant"),
    };
    let _ = secp; // secp no longer needed for signing; left in scope for other call sites

    let request_params = serde_json::json!({
        "transfer_nonce": hex::encode(transfer_nonce),
        "source_deposit_id": hex::encode(info.deposit_id),
        "destination_deposit_id": hex::encode(dest_bytes),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "op_nonce": op_nonce,
        "op_expiry": op_expiry,
        "signature": hex::encode(&signature_bytes),
    });

    // Send request
    let request_id = match transport
        .send_ledger_request(&info.ledger_id, "transfer_lock", request_params)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return serde_json::json!({"success": false, "error": format!("Send failed: {}", e)})
        }
    };

    // Wait for response
    match transport.wait_for_response(&request_id, 10000).await {
        Ok(response) => {
            if response.success {
                serde_json::json!({
                    "success": true,
                    "transfer_id": hex::encode(transfer_id),
                })
            } else {
                let error = response
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string());
                let mut resp = serde_json::json!({
                    "success": false,
                    "error": error,
                });
                // Include balance_msats from result if available
                if let Some(result) = response.result {
                    if let Some(balance) = result.get("balance_msats").and_then(|v| v.as_i64()) {
                        resp.as_object_mut().map(|m| {
                            m.insert(
                                "balance_msats".to_string(),
                                serde_json::Value::Number(balance.into()),
                            )
                        });
                    }
                }
                resp
            }
        }
        Err(e) => serde_json::json!({"success": false, "error": format!("Timeout: {}", e)}),
    }
}

async fn batch_transfer_complete(
    cmd: &serde_json::Value,
    transport: &mut deposits_nostr::NostrTransport,
    _config: &WalletConfig,
) -> serde_json::Value {
    let transfer_id_hex = match cmd.get("transfer_id").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return serde_json::json!({"success": false, "error": "Missing transfer_id"}),
    };
    let preimage_hex = match cmd.get("preimage").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return serde_json::json!({"success": false, "error": "Missing preimage"}),
    };
    let ledger_id = match cmd.get("ledger").and_then(|v| v.as_str()) {
        Some(l) => l,
        None => return serde_json::json!({"success": false, "error": "Missing ledger"}),
    };

    let request_params = serde_json::json!({
        "transfer_id": transfer_id_hex,
        "preimage": preimage_hex,
    });

    // Send request
    let request_id = match transport
        .send_ledger_request(ledger_id, "transfer_complete", request_params)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return serde_json::json!({"success": false, "error": format!("Send failed: {}", e)})
        }
    };

    // Wait for response
    match transport.wait_for_response(&request_id, 10000).await {
        Ok(response) => {
            if response.success {
                serde_json::json!({"success": true})
            } else {
                let error = response
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string());
                serde_json::json!({"success": false, "error": error})
            }
        }
        Err(e) => serde_json::json!({"success": false, "error": format!("Timeout: {}", e)}),
    }
}
