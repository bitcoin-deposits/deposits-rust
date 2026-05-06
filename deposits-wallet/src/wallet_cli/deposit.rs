use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chrono::Utc;

use super::{
    deposit_record_identity, derive_secret_key, derive_secret_key_at_index,
    load_deposit_key_index, parse_config, save_deposit_key_index, verify_offer_cosignature,
    verify_quorum_membership, NostrTransportBuilder,
};

/// Open a new deposit account on a ledger. Only creates the empty
/// account — use `offer <alias> <sats>` afterward to request an
/// on-chain funding address, or fund by lightning / incoming transfer.
pub async fn open_new_deposit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut alias: Option<String> = None;
    let mut cli_fee_bps: Option<u64> = None;
    let mut cli_fee_fixed: Option<u64> = None;
    let mut cli_fee_period: Option<u64> = None;
    let mut lightning_address: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--alias" if i + 1 < args.len() => {
                alias = Some(args[i + 1].clone());
                i += 1;
            }
            "--lightning-address" | "--ln-address" if i + 1 < args.len() => {
                lightning_address = Some(args[i + 1].clone());
                i += 1;
            }
            "--fee-bps" if i + 1 < args.len() => {
                cli_fee_bps = Some(args[i + 1].parse().unwrap_or(0));
                i += 1;
            }
            "--fee-fixed-sats" | "--fee-fixed" if i + 1 < args.len() => {
                cli_fee_fixed = Some(args[i + 1].parse().unwrap_or(0));
                i += 1;
            }
            "--fee-period-blocks" | "--fee-period" if i + 1 < args.len() => {
                cli_fee_period = Some(args[i + 1].parse().unwrap_or(2016));
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
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
                // Extra positional args are ignored — sats used to live
                // here; it belongs on `offer <alias> <sats>` now.
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id
        .ok_or("Usage: deposits-wallet open <ledger_id> [--alias <name>] --relay <url>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Check if alias is already taken
    if let Some(ref a) = alias {
        let deposits_file = config.data_dir.join("deposits.json");
        if deposits_file.exists() {
            let data = std::fs::read_to_string(&deposits_file)?;
            let deposits: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();
            if deposits
                .iter()
                .any(|d| d.get("alias").and_then(|v| v.as_str()) == Some(a))
            {
                return Err(format!(
                    "Alias '{}' is already in use. Use 'list' to see existing deposits.",
                    a
                )
                .into());
            }
        }
    }

    // Get next available key index for this deposit
    let key_index = load_deposit_key_index(&config.data_dir);
    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Also derive the nostr identity key at index 0 for signing requests
    let nostr_key = config.nostr_key()?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Resolve prefix to full ledger ID and fetch advertisement for fees
    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let (ledger_id, advertisement) = if ledger_id.len() < 64 {
        let ads = transport.fetch_ledger_advertisements(network_str).await?;
        let ad = ads
            .into_iter()
            .find(|a| a.ledger_id.starts_with(&ledger_id))
            .ok_or_else(|| format!("No ledger found matching: {}", ledger_id))?;
        let lid = ad.ledger_id.clone();
        (lid, Some(ad))
    } else {
        // Fetch the advertisement for the full ledger ID
        let ad = transport.fetch_ledger_advertisement(&ledger_id).await?;
        (ledger_id, ad)
    };

    println!("Opening deposit account...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    if let Some(ref a) = alias {
        println!("  Alias: {}", a);
    }

    // Get fee structure: CLI flags override, then advertisement, then defaults
    let (fee_fixed, fee_bps, fee_frequency) = if cli_fee_bps.is_some() || cli_fee_fixed.is_some() {
        let bps = cli_fee_bps.unwrap_or(0);
        let period = cli_fee_period.unwrap_or(2016);
        let fixed_sats = cli_fee_fixed.unwrap_or(0);
        let annualized_msats = fixed_sats * 1000 * (52560 / period);
        println!(
            "  Fees: {} bps/year + {} msats/year fixed (CLI override)",
            bps, annualized_msats
        );
        (annualized_msats, bps, period)
    } else if let Some(ref ad) = advertisement {
        let period = if ad.fee_period_blocks > 0 {
            ad.fee_period_blocks
        } else {
            2016
        };
        let fee_struct = ad.to_fee_structure();
        println!(
            "  Fees: {} bps/year + {} sats/year fixed (period: {} blocks)",
            ad.annual_fee_bps, fee_struct.annualized_msats, period
        );
        (
            fee_struct.annualized_msats,
            fee_struct.annualized_bps as u64,
            period as u64,
        )
    } else {
        println!("  Fees: (using defaults - no advertisement found)");
        (0, 0, 2016)
    };
    println!();

    // Send deposit_open request to create the deposit account. Identity
    // is the deposit's miniscript descriptor; deposit_id is its hash.
    // The wallet currently always builds pk(...) — multi-key descriptors
    // would replace this single line.
    let descriptor = format!("pk({})", hex::encode(our_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let open_params = serde_json::json!({
        "descriptor": descriptor,
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending deposit_open request to operator...");

    // One retry after a successful verification round — without this the
    // loop would spin forever on a persistent rejection.
    let mut attempted_verify = false;
    loop {
        let open_request_id = transport
            .send_ledger_request_ext(
                &ledger_id,
                "deposit_open",
                open_params.clone(),
                config.subkey_credential(),
            )
            .await?;

        println!("  Request ID: {}...", &open_request_id[..16]);

        let response = match transport
            .wait_for_valid_response(&open_request_id, 30000, |response| {
                if response.success {
                    return true;
                }
                let error = response.error.as_deref().unwrap_or("");
                if error.contains("already exists") || error.contains("Deposit already") {
                    return true;
                }
                // Also accept attestation_required so the outer flow can run
                // the verifier round-trip and retry. Without this the filter
                // would swallow the rejection as "rogue operator" noise.
                if let Some(result_val) = &response.result {
                    if let Some(code) = result_val.get("code").and_then(|v| v.as_str()) {
                        if code == "attestation_required"
                            || code == "not_authorized"
                            || code == "denied"
                        {
                            return true;
                        }
                    }
                }
                eprintln!("Warning: Rejecting error response: {}", error);
                false
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("Timeout waiting for deposit_open response: {}", e).into());
            }
        };

        if response.success {
            println!("  Deposit account created!");
            break;
        }
        let err_str = response.error.as_deref().unwrap_or("");
        if err_str.contains("already exists") || err_str.contains("Deposit already") {
            println!("  Deposit account already exists, continuing...");
            break;
        }

        // Access control path — inspect the structured error code.
        let code = response
            .result
            .as_ref()
            .and_then(|r| r.get("code"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if code == "attestation_required" && !attempted_verify {
            let verifier_pubkey = response
                .result
                .as_ref()
                .and_then(|r| r.get("verifier_pubkey"))
                .and_then(|v| v.as_str())
                .ok_or(
                    "Operator requires attestation but did not advertise a verifier_pubkey",
                )?;
            let allowed_domains: Vec<String> = response
                .result
                .as_ref()
                .and_then(|r| r.get("allowed_domains"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            run_verification_flow(
                &transport,
                verifier_pubkey,
                &allowed_domains,
                lightning_address.as_deref(),
            )
            .await?;
            attempted_verify = true;
            println!("  Retrying deposit_open...");
            continue;
        }

        if code == "not_authorized" || code == "denied" {
            return Err(format!(
                "Operator rejected deposit (code={}): {}",
                code, err_str
            )
            .into());
        }

        return Err(format!("deposit_open failed: {}", err_str).into());
    }

    // Save the deposit account to local storage. No funding address
    // or amount yet — those come from `offer <alias> <sats>`, which
    // calls make_offer against the operator and writes the returned
    // address + min/max back into this record. Alternatively the
    // account can be funded by incoming lightning or transfer.
    let deposits_file = config.data_dir.join("deposits.json");
    let mut deposits: Vec<serde_json::Value> = if deposits_file.exists() {
        let data = std::fs::read_to_string(&deposits_file)?;
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    };

    let final_alias = alias
        .clone()
        .unwrap_or_else(|| format!("deposit-{}", deposits.len() + 1));

    deposits.push(serde_json::json!({
        "alias": final_alias,
        "ledger_id": ledger_id,
        "deposit_id": hex::encode(deposit_id),
        "descriptor": descriptor,
        "key_index": key_index,
        "status": "open",
        "created_at": Utc::now().to_rfc3339(),
    }));
    std::fs::write(&deposits_file, serde_json::to_string_pretty(&deposits)?)?;

    save_deposit_key_index(&config.data_dir, key_index + 1)?;

    println!();
    println!("Deposit account '{}' created.", final_alias);
    println!();
    println!("Next: request an on-chain funding address with");
    println!("    deposits-wallet offer {} <sats>", final_alias);
    println!("or fund by incoming lightning invoice / transfer.");
    Ok(())
}

fn prompt_stdin(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Drive the lightning-verify service round-trip so the operator will
/// accept a retried `deposit_open`. Mirrors the web wallet's interactive
/// flow (index.html `showVerificationFlow`) but over stdin instead of a
/// modal.
async fn run_verification_flow(
    transport: &deposits_nostr::NostrTransport,
    verifier_pubkey: &str,
    allowed_domains: &[String],
    cli_lightning_address: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    println!();
    println!("Operator requires a lightning-verify attestation.");
    println!("  verifier:  {}...", &verifier_pubkey[..16.min(verifier_pubkey.len())]);
    if !allowed_domains.is_empty() {
        println!("  domains:   {}", allowed_domains.join(", "));
    }

    // Lightning address: flag > stdin prompt.
    let address = match cli_lightning_address {
        Some(a) => a.to_string(),
        None => {
            let hint = allowed_domains
                .first()
                .map(String::as_str)
                .unwrap_or("domain.com");
            prompt_stdin(&format!(
                "Enter your lightning address (e.g. alice@{}): ",
                hint
            ))?
        }
    };
    if !address.contains('@') {
        return Err(format!("'{}' doesn't look like a lightning address", address).into());
    }

    // ── Round 1: request verification for address ──
    println!("Requesting verification for {}...", address);
    let req_id = transport
        .send_verify_request(
            verifier_pubkey,
            serde_json::json!({ "lightning_address": address }),
        )
        .await?;
    let resp = transport.wait_for_verify_response(&req_id, 30_000).await?;

    match resp.get("status").and_then(|v| v.as_str()) {
        Some("already_verified") => {
            println!("Already verified.");
            return Ok(());
        }
        Some("verified") => {
            println!("Verified via NIP-05.");
            if let Some(id) = resp.get("attestation_event_id").and_then(|v| v.as_str()) {
                println!("  attestation: {}...", &id[..16.min(id.len())]);
            }
            return Ok(());
        }
        _ => {}
    }

    let invoice = resp
        .get("invoice")
        .and_then(|v| v.as_str())
        .ok_or("Verifier returned neither `verified` status nor an invoice")?;
    let session_id = resp
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("Verifier did not return a session_id")?
        .to_string();
    let amount_sats = resp
        .get("amount_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!();
    println!("Pay {} sats to verify your address:", amount_sats);
    println!();
    println!("  {}", invoice);
    println!();
    println!("Waiting for payment (polling every 3s, up to 3 minutes)...");

    // ── Round 2: poll until challenge_sent ──
    let mut attempts = 0u32;
    loop {
        if attempts >= 60 {
            return Err("Payment not detected after 3 minutes — try again".into());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        attempts += 1;

        let cr = transport
            .send_verify_request(
                verifier_pubkey,
                serde_json::json!({
                    "action": "challenge",
                    "session_id": &session_id,
                }),
            )
            .await?;
        let cresp = transport.wait_for_verify_response(&cr, 10_000).await?;
        match cresp.get("status").and_then(|v| v.as_str()) {
            Some("challenge_sent") => {
                println!();
                if let Some(msg) = cresp.get("message").and_then(|v| v.as_str()) {
                    println!("{}", msg);
                }
                break;
            }
            Some("payment_pending") => {
                // stay quiet between polls; single dot to show progress
                use std::io::Write;
                print!(".");
                std::io::stdout().flush().ok();
            }
            other => {
                let msg = cresp
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| other.unwrap_or("unknown"));
                return Err(format!("Challenge failed: {}", msg).into());
            }
        }
    }

    // ── Round 3: submit amounts ──
    let amounts_str = prompt_stdin(
        "Enter the amounts you received (comma-separated, e.g. 123,456,789): ",
    )?;
    let amounts: Vec<u64> = amounts_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .collect();
    if amounts.is_empty() {
        return Err("No amounts parsed".into());
    }

    println!("Submitting amounts...");
    let vr = transport
        .send_verify_request(
            verifier_pubkey,
            serde_json::json!({
                "action": "verify",
                "session_id": &session_id,
                "amounts": amounts,
            }),
        )
        .await?;
    let vresp = transport.wait_for_verify_response(&vr, 30_000).await?;

    match vresp.get("status").and_then(|v| v.as_str()) {
        Some("verified") => {
            println!("Verified.");
            if let Some(id) = vresp.get("attestation_event_id").and_then(|v| v.as_str()) {
                println!("  attestation: {}...", &id[..16.min(id.len())]);
            }
            Ok(())
        }
        _ => {
            let msg = vresp
                .get("message")
                .or_else(|| vresp.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("Verification failed");
            Err(msg.into())
        }
    }
}

/// Add funds to an existing deposit
pub async fn add_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if alias.is_none() {
            alias = Some(args[i].clone());
        } else if amount_sats.is_none() {
            amount_sats = Some(args[i].parse()?);
        }
        i += 1;
    }

    let alias = alias.ok_or("Usage: deposits-wallet offer <alias> <amount_sats> --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a new deposit first.".into());
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

    println!("Adding funds to deposit...");
    println!("  Alias: {}", alias);
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    println!();

    // Get the key_index for this deposit (defaults to 0 for legacy deposits)
    let key_index = deposit
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Source descriptor of truth: deposits.json. New records carry it
    // directly; older records only have `deposit_pubkey`, in which case
    // we synthesize the pk(...) descriptor on the fly.
    let descriptor = if let Some(d) = deposit.get("descriptor").and_then(|v| v.as_str()) {
        d.to_string()
    } else if let Some(pk) = deposit.get("deposit_pubkey").and_then(|v| v.as_str()) {
        format!("pk({})", pk)
    } else {
        format!("pk({})", hex::encode(our_pubkey.serialize()))
    };

    // Use nostr identity key (index 0) for transport signing
    let nostr_key = config.nostr_key()?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Fetch advertisement for fee structure
    let advertisement = transport.fetch_ledger_advertisement(ledger_id).await?;
    let (fee_fixed, fee_bps, fee_frequency) = if let Some(ref ad) = advertisement {
        let period = if ad.fee_period_blocks > 0 {
            ad.fee_period_blocks
        } else {
            2016
        };
        let fee_struct = ad.to_fee_structure();
        (
            fee_struct.annualized_msats,
            fee_struct.annualized_bps as u64,
            period as u64,
        )
    } else {
        (0, 0, 2016)
    };

    // Send make_offer request for existing deposit
    let request_params = serde_json::json!({
        "descriptor": descriptor,
        "max_sats": amount_sats,
        "min_sats": 1000_u64,
        "blocks_valid": 144_u64,
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending offer request to operator...");

    let request_id = transport
        .send_ledger_request(ledger_id, "make_offer", request_params)
        .await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

    // Wait for response using real-time subscription
    match transport.wait_for_response(&request_id, 60000).await {
        Ok(response) => {
            if response.success {
                println!("Offer accepted!");
                let result = response.result.as_ref();
                let funding_address = result
                    .and_then(|r| r.get("funding_address").and_then(|v| v.as_str()))
                    .map(|s| s.to_string());
                let offer_id = result
                    .and_then(|r| r.get("offer_id").and_then(|v| v.as_str()))
                    .map(|s| s.to_string());

                if let Some(ref address) = funding_address {
                    println!();
                    println!("Send {} sats to:", amount_sats);
                    println!("  {}", address);
                    println!();
                    println!("After funding, the deposit will be automatically completed.");
                }
                if let Some(ref id) = offer_id {
                    println!("Offer ID: {}", id);
                }

                // Persist offer details back into the deposit record so
                // downstream commands (regtest-faucet, list) can see them.
                let mut deposits: Vec<serde_json::Value> =
                    serde_json::from_str(&std::fs::read_to_string(&deposits_file)?)?;
                for d in deposits.iter_mut() {
                    if d.get("alias").and_then(|v| v.as_str()) == Some(&alias) {
                        if let Some(obj) = d.as_object_mut() {
                            if let Some(addr) = &funding_address {
                                obj.insert(
                                    "funding_address".to_string(),
                                    serde_json::Value::String(addr.clone()),
                                );
                            }
                            if let Some(id) = &offer_id {
                                obj.insert(
                                    "offer_id".to_string(),
                                    serde_json::Value::String(id.clone()),
                                );
                            }
                            obj.insert(
                                "min_sats".to_string(),
                                serde_json::Value::Number(1000u64.into()),
                            );
                            obj.insert(
                                "max_sats".to_string(),
                                serde_json::Value::Number(amount_sats.into()),
                            );
                        }
                        break;
                    }
                }
                std::fs::write(&deposits_file, serde_json::to_string_pretty(&deposits)?)?;

                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                Err(format!("Offer request failed: {}", error).into())
            }
        }
        Err(e) => Err(format!("Timeout waiting for operator response: {}", e).into()),
    }
}

/// List all deposits with aliases
pub async fn list_deposits(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits found.");
        println!();
        println!("To open a deposit:");
        println!("  deposits-wallet discover --relay <url>");
        println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name> --relay <url>");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits found.");
        return Ok(());
    }

    println!("Your Deposits");
    println!("=============");
    println!();

    for deposit in &deposits {
        let alias = deposit
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        let ledger_id = deposit
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let amount = deposit
            .get("amount_sats")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let status = deposit
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let created_at = deposit
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (descriptor, deposit_id_hex) = deposit_record_identity(deposit)
            .unwrap_or(("unknown".into(), "unknown".into()));

        println!("  {} ", alias);
        println!("    Deposit ID:  {}", deposit_id_hex);
        println!("    Descriptor:  {}", descriptor);
        println!(
            "    Ledger:      {}...",
            &ledger_id[..16.min(ledger_id.len())]
        );
        println!("    Amount:      {} sats", amount);
        println!("    Status:      {}", status);
        if !created_at.is_empty() {
            println!("    Created:     {}", created_at);
        }
        println!();
    }

    println!("Commands:");
    println!("  offer <alias> <sats>      Add funds to a deposit");
    println!("  withdraw <alias> <sats>   Withdraw from a deposit");
    println!("  history <alias>           View transaction history");

    Ok(())
}

/// Show balances across all deposits
pub async fn show_balance(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Auto-sync if relay is provided
    if !config.relays.is_empty() {
        if let Err(e) = sync_deposits(args).await {
            // Don't fail on sync error, just log it
            eprintln!("Note: sync failed: {}", e);
        }
    }

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits found.");
        println!();
        println!("To open a deposit:");
        println!("  deposits-wallet discover --relay <url>");
        println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name> --relay <url>");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits found.");
        return Ok(());
    }

    println!("Deposit Balances");
    println!("================");
    println!();

    let mut total_sats = 0u64;

    let mut total_locked = 0u64;

    for deposit in &deposits {
        let alias = deposit
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        let id_hex = deposit_record_identity(deposit)
            .map(|(_, id)| id)
            .unwrap_or_else(|| "unknown".into());
        let amount = deposit
            .get("amount_sats")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let locked = deposit
            .get("locked_sats")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let status = deposit
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let status_symbol = match status {
            "completed" | "funded" => "+",
            "pending" => "~",
            _ => "?",
        };

        let id_short = &id_hex[..8.min(id_hex.len())];
        if locked > 0 {
            println!(
                "  {} {} {:>10} sats  ({})  [{} pending]",
                status_symbol, alias, amount, id_short, locked
            );
        } else {
            println!(
                "  {} {} {:>10} sats  ({})",
                status_symbol, alias, amount, id_short
            );
        }

        if status == "funded" || status == "completed" {
            total_sats += amount;
            total_locked += locked;
        }
    }

    println!();
    if total_locked > 0 {
        println!(
            "  Total:  {} sats ({} BTC)  [{} pending]",
            total_sats,
            total_sats as f64 / 100_000_000.0,
            total_locked
        );
    } else {
        println!(
            "  Total:  {} sats ({} BTC)",
            total_sats,
            total_sats as f64 / 100_000_000.0
        );
    }
    println!();
    println!("  + = funded/completed, ~ = pending, [N pending] = locked for withdrawal");

    Ok(())
}

/// Sync deposit statuses from the daemon
pub async fn sync_deposits(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits to sync.");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let mut deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits to sync.");
        return Ok(());
    }

    // Generate our secret key for signing requests
    let secret_key = SecretKey::from_slice(&config.seed)?;

    // Connect to all relays so we can see responses from any operator's primary relay
    let transport = NostrTransportBuilder::new(secret_key)
        .relays(config.relays.iter().cloned())
        .build()
        .await?;

    // Set response filter for relay-side #l tag filtering (reduces fan-out)
    {
        let ledger_ids: Vec<String> = deposits
            .iter()
            .filter_map(|d| {
                d.get("ledger_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        if !ledger_ids.is_empty() {
            transport.set_response_ledger_filter(ledger_ids);
        }
    }

    // Subscribe to responses before sending requests
    if let Err(e) = transport.subscribe_to_response("").await {
        eprintln!("Warning: failed to subscribe to responses: {}", e);
    }

    // Brief delay to let subscription propagate
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    println!("Syncing deposit statuses...");

    let mut updated = false;

    for deposit in &mut deposits {
        let alias = deposit
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let offer_id = deposit
            .get("offer_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let ledger_id = deposit
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let identity = deposit_record_identity(deposit);
        let deposit_id_hex = identity.as_ref().map(|(_, id)| id.clone());
        let current_status = deposit
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // If we have a deposit_id, use balance_query (works for all funded deposits).
        // More reliable than offer_status since the daemon may have cleaned up offers.
        if let (Some(ledger_id), Some(ref deposit_id_hex)) =
            (ledger_id.as_ref(), deposit_id_hex.as_ref())
        {
            if !deposit_id_hex.is_empty() {
                let params = serde_json::json!({
                    "deposit_id": deposit_id_hex,
                });

                let request_id = transport
                    .send_ledger_request(ledger_id, "balance_query", params)
                    .await?;
                eprintln!("  {} sent balance_query ({}...)", alias, &request_id[..16]);

                // Give daemon a moment to process
                tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

                // Wait for response (with timeout)
                let start = std::time::Instant::now();
                let timeout = std::time::Duration::from_secs(8);
                let mut attempts = 0;

                while start.elapsed() < timeout {
                    attempts += 1;
                    match transport.fetch_response(&request_id).await {
                        Ok(Some(response)) => {
                            if response.success {
                                if let Some(result) = &response.result {
                                    // Get balance and locked from response
                                    let balance_msats = result
                                        .get("balance_msats")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let locked_msats = result
                                        .get("locked_msats")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let available_sats =
                                        (balance_msats.saturating_sub(locked_msats)) / 1000;
                                    let locked_sats = locked_msats / 1000;

                                    let current_amount = deposit
                                        .get("amount_sats")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let current_locked = deposit
                                        .get("locked_sats")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);

                                    if available_sats != current_amount
                                        || locked_sats != current_locked
                                    {
                                        if locked_sats > 0 {
                                            println!(
                                                "  {} balance: {} sats ({} pending)",
                                                alias, available_sats, locked_sats
                                            );
                                        } else {
                                            println!(
                                                "  {} balance: {} sats",
                                                alias, available_sats
                                            );
                                        }
                                        deposit["amount_sats"] = serde_json::json!(available_sats);
                                        deposit["balance_msats"] =
                                            serde_json::json!(balance_msats as i64);
                                        deposit["locked_sats"] = serde_json::json!(locked_sats);
                                        updated = true;
                                    }

                                    // Promote status to "funded" if daemon reports a balance
                                    if balance_msats > 0 && current_status == "pending" {
                                        deposit["status"] = serde_json::json!("funded");
                                        updated = true;
                                    }
                                }
                            } else {
                                eprintln!("  {} query failed: {:?}", alias, response.error);
                            }
                            break;
                        }
                        Ok(None) => {
                            // No response yet, keep polling
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                        }
                        Err(e) => {
                            eprintln!("  {} fetch error: {}", alias, e);
                            break;
                        }
                    }
                }
                if start.elapsed() >= timeout {
                    eprintln!("  {} timeout after {} attempts", alias, attempts);
                }
            }
            continue;
        }

        if let (Some(ref offer_id), Some(ledger_id)) = (offer_id.as_ref(), ledger_id.as_ref()) {
            // Query daemon for offer status. Include deposit_id so the
            // daemon can check the ledger directly if the offer record
            // has already been cleaned up.
            let params = if let Some(ref id_hex) = deposit_id_hex {
                serde_json::json!({
                    "offer_id": offer_id,
                    "deposit_id": id_hex,
                })
            } else {
                serde_json::json!({
                    "offer_id": offer_id,
                })
            };

            let request_id = transport
                .send_ledger_request(ledger_id, "offer_status", params)
                .await?;

            // Wait for response (with timeout)
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(10);

            while start.elapsed() < timeout {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                match transport.fetch_response(&request_id).await {
                    Ok(Some(response)) => {
                        if response.success {
                            if let Some(result) = &response.result {
                                // Get status from response
                                if let Some(status_obj) = result.get("status") {
                                    let status_str =
                                        status_obj.get("status").and_then(|v| v.as_str());
                                    let amount =
                                        status_obj.get("amount_sats").and_then(|v| v.as_u64());

                                    if let Some(status_str) = status_str {
                                        if status_str != current_status.as_str() {
                                            println!(
                                                "  {} {} -> {}",
                                                alias, current_status, status_str
                                            );

                                            // Update status
                                            deposit["status"] = serde_json::json!(status_str);

                                            // Update amount if completed
                                            if let Some(amt) = amount {
                                                deposit["amount_sats"] = serde_json::json!(amt);
                                            }

                                            updated = true;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                    Ok(None) => {
                        // No response yet, keep polling
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }

    if updated {
        // Save updated deposits
        let data = serde_json::to_string_pretty(&deposits)?;
        std::fs::write(&deposits_file, data)?;
        println!("Deposits updated.");
    } else {
        println!("All deposits up to date.");
    }

    Ok(())
}
