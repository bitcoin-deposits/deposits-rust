use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chrono::Utc;

use super::{
    derive_secret_key, derive_secret_key_at_index, load_deposit_key_index, parse_config,
    save_deposit_key_index, verify_offer_cosignature, verify_quorum_membership,
    NostrTransportBuilder,
};

/// Open a new deposit on a ledger
pub async fn open_new_deposit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;

    let mut ledger_id: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut alias: Option<String> = None;
    let mut skip_cosign_verify = false;
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
            "--skip-cosign-verify" => {
                skip_cosign_verify = true;
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
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or(
        "Usage: deposits-wallet open <ledger_id> <amount_sats> [--alias <name>] --relay <url>",
    )?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
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

    println!("Opening deposit...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
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

    // Step 1: Send deposit_open request to create the deposit account
    let open_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
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
            .send_ledger_request(&ledger_id, "deposit_open", open_params.clone())
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

    // Step 2: Send make_offer request to get a funding address
    // max_sats = requested amount, min_sats = 1 (or less than max), blocks_valid = 144 (~1 day)
    let min_sats = std::cmp::min(1000_u64, amount_sats.saturating_sub(1).max(1));
    let offer_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "max_sats": amount_sats,
        "min_sats": min_sats,
        "blocks_valid": 144_u64,
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending make_offer request for funding address...");

    let request_id = transport
        .send_ledger_request(&ledger_id, "make_offer", offer_params)
        .await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Wait for a valid response using real-time subscription
    // For co-signature validation, we may reject invalid responses and wait for valid ones
    println!("Waiting for operator response...");

    let ledger_id_clone = ledger_id.clone();
    let response = transport
        .wait_for_valid_response(&request_id, 60000, |response| {
            // Reject error responses from rogue operators and wait for a valid one
            if !response.success {
                let error = response.error.as_deref().unwrap_or("");
                eprintln!("Warning: Rejecting error response: {}", error);
                return false;
            }

            // Check if co-signature validation is needed
            if let Some(result) = &response.result {
                let cosign_required = result
                    .get("cosign_required")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !cosign_required {
                    return true; // No co-signature needed, accept
                }

                // Validate co-signature fields
                let address = result.get("funding_address").and_then(|v| v.as_str());
                let offer_id_hex = result.get("offer_id").and_then(|v| v.as_str());
                let operator_id_str = result.get("operator_id").and_then(|v| v.as_str());
                let deadline_block = result.get("deadline_block").and_then(|v| v.as_u64());
                let cosigner_pubkey_str = result.get("cosigner_pubkey").and_then(|v| v.as_str());
                let cosigner_ledger_hash_hex =
                    result.get("cosigner_ledger_hash").and_then(|v| v.as_str());
                let cosign_signature_hex = result.get("cosign_signature").and_then(|v| v.as_str());

                if let (
                    Some(addr),
                    Some(offer_hex),
                    Some(op_str),
                    Some(deadline),
                    Some(cosigner_str),
                    Some(hash_hex),
                    Some(sig_hex),
                ) = (
                    address,
                    offer_id_hex,
                    operator_id_str,
                    deadline_block,
                    cosigner_pubkey_str,
                    cosigner_ledger_hash_hex,
                    cosign_signature_hex,
                ) {
                    // Parse and verify co-signature
                    let offer_id_bytes: [u8; 32] = match hex::decode(offer_hex) {
                        Ok(b) if b.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            eprintln!("Warning: Invalid offer_id format, rejecting response");
                            return false;
                        }
                    };

                    let cosigner_pubkey = match PublicKey::from_str(cosigner_str) {
                        Ok(pk) => pk,
                        Err(_) => {
                            eprintln!("Warning: Invalid cosigner_pubkey, rejecting response");
                            return false;
                        }
                    };

                    let operator_id = match PublicKey::from_str(op_str) {
                        Ok(pk) => pk,
                        Err(_) => {
                            eprintln!("Warning: Invalid operator_id, rejecting response");
                            return false;
                        }
                    };

                    let member_ledger_hash: [u8; 32] = match hex::decode(hash_hex) {
                        Ok(b) if b.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            eprintln!("Warning: Invalid cosigner_ledger_hash, rejecting response");
                            return false;
                        }
                    };

                    let signature: [u8; 64] = match hex::decode(sig_hex) {
                        Ok(b) if b.len() == 64 => {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            eprintln!("Warning: Invalid cosign_signature, rejecting response");
                            return false;
                        }
                    };

                    // Verify the signature
                    if !verify_offer_cosignature(
                        &ledger_id_clone,
                        &offer_id_bytes,
                        &operator_id,
                        addr,
                        deadline as u32,
                        &cosigner_pubkey,
                        &member_ledger_hash,
                        &signature,
                    ) {
                        eprintln!(
                            "Warning: Invalid co-signature, rejecting response from rogue operator"
                        );
                        return false;
                    }

                    // Note: quorum membership check happens after we accept the response
                    // since it requires async call which we can't do in the validator
                    true
                } else {
                    eprintln!(
                        "Warning: Response requires co-signature but missing fields, rejecting"
                    );
                    false
                }
            } else {
                true // Accept responses without result (will be handled as error below)
            }
        })
        .await?;

    // Process the accepted response
    if !response.success {
        let error = response.error.as_deref().unwrap_or("Unknown error");
        return Err(format!("Deposit request failed: {}", error).into());
    }

    let result = response
        .result
        .as_ref()
        .ok_or("Response missing result data")?;

    let address = result
        .get("funding_address")
        .and_then(|v| v.as_str())
        .ok_or("Response missing funding_address")?;
    let offer_id_hex = result
        .get("offer_id")
        .and_then(|v| v.as_str())
        .ok_or("Response missing offer_id")?;
    let min_sats = result.get("min_sats").and_then(|v| v.as_u64()).unwrap_or(1);
    let max_sats = result
        .get("max_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(amount_sats);

    // Verify quorum membership for co-signed responses (async check)
    let cosign_required = result
        .get("cosign_required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if cosign_required && !skip_cosign_verify {
        if let Some(cosigner_str) = result.get("cosigner_pubkey").and_then(|v| v.as_str()) {
            if let Ok(cosigner_pubkey) = PublicKey::from_str(cosigner_str) {
                if !verify_quorum_membership(&transport, &ledger_id, &cosigner_pubkey).await {
                    return Err("Cosigner is not a quorum member".into());
                }
                println!(
                    "  Co-signature verified from quorum member {}...",
                    &cosigner_str[..16.min(cosigner_str.len())]
                );
            }
        }
    } else if cosign_required && skip_cosign_verify {
        println!("  Skipping co-signature verification (--skip-cosign-verify)");
    }

    // Save deposit to local storage with alias
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
        "offer_id": offer_id_hex,
        "ledger_id": ledger_id,
        "funding_address": address,
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "key_index": key_index,
        "min_sats": min_sats,
        "max_sats": max_sats,
        "status": "pending",
        "created_at": Utc::now().to_rfc3339(),
    }));
    std::fs::write(&deposits_file, serde_json::to_string_pretty(&deposits)?)?;

    save_deposit_key_index(&config.data_dir, key_index + 1)?;

    println!("Deposit '{}' created!", final_alias);
    println!();
    println!("Fund with {}-{} sats:", min_sats, max_sats);
    println!("  {}", address);
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
    transport: &deposits_node::nostr::NostrTransport,
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

    let deposit_pubkey = deposit.get("deposit_pubkey").and_then(|v| v.as_str());

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

    // Use stored pubkey or derive fresh (should match what's in the record)
    let pubkey_hex = deposit_pubkey
        .map(|s| s.to_string())
        .unwrap_or_else(|| hex::encode(our_pubkey.serialize()));

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
        "deposit_pubkey": pubkey_hex,
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
                if let Some(result) = &response.result {
                    if let Some(address) = result.get("funding_address").and_then(|v| v.as_str()) {
                        println!();
                        println!("Send {} sats to:", amount_sats);
                        println!("  {}", address);
                        println!();
                        println!("After funding, the deposit will be automatically completed.");
                    }
                    if let Some(offer_id) = result.get("offer_id").and_then(|v| v.as_str()) {
                        println!("Offer ID: {}", offer_id);
                    }
                }
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
        let deposit_pubkey = deposit
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Compute descriptor and deposit_id from pubkey
        let descriptor = if !deposit_pubkey.is_empty() {
            format!("pk({})", deposit_pubkey)
        } else {
            "unknown".to_string()
        };
        let deposit_id = if !deposit_pubkey.is_empty() {
            use bitcoin::hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(descriptor.as_bytes());
            hex::encode(&hash[..16])
        } else {
            "unknown".to_string()
        };

        println!("  {} ", alias);
        println!("    Deposit ID:  {}", deposit_id);
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
        let deposit_pubkey = deposit
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
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

        if locked > 0 {
            println!(
                "  {} {} {:>10} sats  ({})  [{} pending]",
                status_symbol,
                alias,
                amount,
                &deposit_pubkey[..8.min(deposit_pubkey.len())],
                locked
            );
        } else {
            println!(
                "  {} {} {:>10} sats  ({})",
                status_symbol,
                alias,
                amount,
                &deposit_pubkey[..8.min(deposit_pubkey.len())]
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
        let deposit_pubkey = deposit
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let current_status = deposit
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // If we have deposit_pubkey, use balance_query (works for all funded deposits)
        // This is more reliable than offer_status since the daemon may have cleaned up offers
        if let (Some(ledger_id), Some(ref deposit_pubkey)) =
            (ledger_id.as_ref(), deposit_pubkey.as_ref())
        {
            if !deposit_pubkey.is_empty() {
                let params = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey,
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
            // Query daemon for offer status
            // Include deposit_pubkey so daemon can check ledger if offer not found
            let params = if let Some(ref pubkey) = deposit_pubkey {
                serde_json::json!({
                    "offer_id": offer_id,
                    "deposit_pubkey": pubkey,
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
