//! Swap advertisement commands: publish and discover bilateral peer-swap offers.
//!
//! `swap-advertise`: publish a SwapAdvertisement (Kind 39103) from an owned deposit,
//! signaling openness to swap funds out of one ledger in exchange for funds on
//! another. `swap-list`: discover open swap ads on the network.
//!
//! Negotiation and execution (bilateral HTLC) are handled in a follow-up.

use deposits_core::messages::LedgerOperation;
use deposits_core::signature_utils::{compute_transfer_id, transfer_lock_signing_message};
use deposits_core::tlv::TlvDecode;
use deposits_core::types::{compute_deposit_id, TransferFeeSchedule};
use deposits_nostr::{SwapAdvertisement, SwapRequest, SwapResponse};

use super::{derive_secret_key, derive_secret_key_at_index, parse_config, NostrTransportBuilder};

// ────────────────────────── HTLC execution helpers ──────────────────────────

fn default_operator_fee(amount_msats: u64) -> u64 {
    let sched = TransferFeeSchedule::default();
    sched
        .fixed_msats
        .saturating_add(amount_msats.saturating_mul(sched.rate_bps as u64) / 10_000)
}

async fn current_block_for(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    let ad = transport
        .fetch_ledger_advertisement(ledger_id)
        .await?
        .ok_or_else(|| format!("No advertisement for {}", &ledger_id[..16]))?;
    if ad.current_block == 0 {
        return Err("Operator does not advertise current_block".into());
    }
    Ok(ad.current_block)
}

/// Configure the transport's response filter to cover both swap legs.
/// Must be called BEFORE any send_ledger_request on either ledger — the
/// response subscription is set up lazily on the first call and is pinned
/// to the filter at that moment (see nostr::subscribe_to_response).
fn configure_swap_response_filter(
    transport: &deposits_nostr::NostrTransport,
    left_ledger: &str,
    right_ledger: &str,
) {
    transport.set_response_ledger_filter(vec![
        left_ledger.to_string(),
        right_ledger.to_string(),
    ]);
    // Clear the subscription flag so the next send re-subscribes with the
    // updated filter (first send set it to a single-ledger filter).
    transport.clear_response_subscription();
}

/// Submit a TransferLock via the operator. Returns the transfer_id.
async fn submit_transfer_lock(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
    source_sk: &bitcoin::secp256k1::SecretKey,
    source_deposit_id: [u8; 16],
    dest_deposit_id: [u8; 16],
    amount_msats: u64,
    operator_fee_msats: u64,
    completion_script: &str,
    timeout_height: u32,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, source_sk);

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let msg_hash = transfer_lock_signing_message(
        &nonce,
        &source_deposit_id,
        &dest_deposit_id,
        amount_msats,
        operator_fee_msats,
        completion_script,
        timeout_height,
    );
    let transfer_id = compute_transfer_id(&msg_hash);
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(source_deposit_id),
        "destination_deposit_id": hex::encode(dest_deposit_id),
        "amount": amount_msats,
        "fee": operator_fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

    let req_id = transport
        .send_ledger_request(ledger_id, "transfer_lock", params)
        .await?;
    let resp = transport.wait_for_response(&req_id, 10_000).await?;
    if !resp.success {
        return Err(format!(
            "transfer_lock rejected: {}",
            resp.error.as_deref().unwrap_or("unknown")
        )
        .into());
    }
    Ok(transfer_id)
}

async fn submit_transfer_complete(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
    transfer_id: [u8; 32],
    preimage: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let params = serde_json::json!({
        "transfer_id": hex::encode(transfer_id),
        "preimage": hex::encode(preimage),
    });
    let req_id = transport
        .send_ledger_request(ledger_id, "transfer_complete", params)
        .await?;
    let resp = transport.wait_for_response(&req_id, 10_000).await?;
    if !resp.success {
        return Err(format!(
            "transfer_complete rejected: {}",
            resp.error.as_deref().unwrap_or("unknown")
        )
        .into());
    }
    Ok(())
}

/// Poll `ledger_id` until a TransferLock matching (hash, dest, amount) lands,
/// returning its transfer_id.
async fn watch_for_lock(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
    hash_hex: &str,
    dest_deposit_id: [u8; 16],
    expected_amount: u64,
    timeout_sec: u64,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let expected_script = format!("sha256({})", hash_hex);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_sec);
    loop {
        let updates = transport.fetch_ledger_updates(ledger_id).await?;
        for update in updates.iter().rev() {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::TransferLock {
                    destination_deposit_id,
                    amount,
                    completion_script,
                    transfer_id,
                    ..
                } = op
                {
                    if destination_deposit_id == dest_deposit_id
                        && amount == expected_amount
                        && completion_script == expected_script
                    {
                        return Ok(transfer_id);
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                format!("timeout waiting for transfer_lock on {}", &ledger_id[..16]).into(),
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
}

/// Poll `ledger_id` for the TransferComplete matching `transfer_id`, extract
/// the revealed preimage.
async fn watch_for_reveal(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
    transfer_id: [u8; 32],
    timeout_sec: u64,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_sec);
    loop {
        let updates = transport.fetch_ledger_updates(ledger_id).await?;
        for update in updates.iter().rev() {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::TransferComplete {
                    transfer_id: tid,
                    script_witness,
                } = op
                {
                    if tid == transfer_id {
                        if let Some(preimage_bytes) = script_witness.stack.first() {
                            if preimage_bytes.len() == 32 {
                                let mut preimage = [0u8; 32];
                                preimage.copy_from_slice(preimage_bytes);
                                return Ok(preimage);
                            }
                        }
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timeout waiting for TransferComplete on {}",
                &ledger_id[..16]
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
}

/// Find a deposit record whose computed deposit_id matches `target`.
fn find_deposit_by_id<'a>(
    deposits: &'a [serde_json::Value],
    config: &super::WalletConfig,
    target: [u8; 16],
) -> Option<&'a serde_json::Value> {
    deposits.iter().find(|d| {
        let key_index = d.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let sk = match derive_secret_key_at_index(&config.seed, config.network, key_index) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk).public_key();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        compute_deposit_id(&descriptor) == target
    })
}

/// Publish a SwapAdvertisement from one of this wallet's deposits.
///
/// Usage: deposits-wallet swap-advertise <alias> <available_sats>
///          [--desired <ledger_id>,<ledger_id>...]
///          [--fee-bps <n>] [--fee-fixed <msats>]
///          [--min-swap <sats>] [--max-swap <sats>]
///          [--expires-hours <h>] [--note <text>]
///          --relay <url>
pub async fn swap_advertise(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut available_sats: Option<u64> = None;
    let mut desired_ledgers: Vec<String> = Vec::new();
    let mut fee_rate_bps: u16 = 0;
    let mut fee_fixed_msats: u64 = 0;
    let mut min_swap_sats: u64 = 0;
    let mut max_swap_sats: u64 = 0;
    let mut expires_hours: u64 = 24;
    let mut note: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--desired" if i + 1 < args.len() => {
                desired_ledgers = args[i + 1]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                i += 1;
            }
            "--fee-bps" if i + 1 < args.len() => {
                fee_rate_bps = args[i + 1].parse()?;
                i += 1;
            }
            "--fee-fixed" if i + 1 < args.len() => {
                fee_fixed_msats = args[i + 1].parse()?;
                i += 1;
            }
            "--min-swap" if i + 1 < args.len() => {
                min_swap_sats = args[i + 1].parse()?;
                i += 1;
            }
            "--max-swap" if i + 1 < args.len() => {
                max_swap_sats = args[i + 1].parse()?;
                i += 1;
            }
            "--expires-hours" if i + 1 < args.len() => {
                expires_hours = args[i + 1].parse()?;
                i += 1;
            }
            "--note" if i + 1 < args.len() => {
                note = Some(args[i + 1].clone());
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
                } else if available_sats.is_none() {
                    available_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or(
        "Usage: deposits-wallet swap-advertise <alias> <available_sats> [options] --relay <url>",
    )?;
    let available_sats = available_sats.ok_or("Missing available_sats")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    let data = std::fs::read_to_string(&deposits_file)
        .map_err(|_| "No deposits found. Use 'open' to create a deposit first.")?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'", alias))?;

    let ledger_id = deposit
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?
        .to_string();

    let key_index = deposit
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let sk = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pk = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk).public_key();
    let descriptor = format!("pk({})", hex::encode(pk.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);

    let nostr_key = config.nostr_key()?;
    let nostr_pk =
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &nostr_key);
    // Nostr pubkeys are x-only (BIP-340, 32 bytes), not compressed secp256k1.
    // The p-tag and event.pubkey both use x-only form.
    let (xonly_pk, _parity) = nostr_pk.x_only_public_key();

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = if expires_hours == 0 {
        0
    } else {
        now + expires_hours * 3600
    };

    let ad = SwapAdvertisement {
        maker_pubkey: hex::encode(xonly_pk.serialize()),
        network: network_str.to_string(),
        source_ledger: ledger_id.clone(),
        source_deposit_id: hex::encode(deposit_id),
        available_msats: available_sats.saturating_mul(1000),
        desired_ledgers: desired_ledgers.clone(),
        fee_fixed_msats,
        fee_rate_bps,
        min_swap_msats: min_swap_sats.saturating_mul(1000),
        max_swap_msats: max_swap_sats.saturating_mul(1000),
        relay_url: Some(config.relays[0].clone()),
        expires_at,
        note,
        event_id: String::new(),
        timestamp: 0,
    };

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    println!("Publishing swap advertisement...");
    println!("  From:     {} on {}...", alias, &ledger_id[..16]);
    println!("  Offering: {} sats", available_sats);
    if desired_ledgers.is_empty() {
        println!("  Desired:  (no preference)");
    } else {
        println!("  Desired:  {} ledger(s)", desired_ledgers.len());
        for lid in &desired_ledgers {
            println!("            {}...", &lid[..16.min(lid.len())]);
        }
    }
    if fee_fixed_msats > 0 || fee_rate_bps > 0 {
        println!(
            "  Fee:      {} msats + {} bps",
            fee_fixed_msats, fee_rate_bps
        );
    }
    if expires_at > 0 {
        println!("  Expires:  in {} hour(s)", expires_hours);
    }

    let event_id = transport.publish_swap_advertisement(&ad).await?;
    println!();
    println!("Published.");
    println!("  Event ID: {}", event_id);

    Ok(())
}

/// Discover open swap advertisements on the network.
///
/// Usage: deposits-wallet swap-list [--source <ledger_id>] [--desired <ledger_id>]
///                                  [--json] --relay <url>
pub async fn swap_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut filter_source: Option<String> = None;
    let mut filter_desired: Option<String> = None;
    let mut json_output = false;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" if i + 1 < args.len() => {
                filter_source = Some(args[i + 1].clone());
                i += 1;
            }
            "--desired" if i + 1 < args.len() => {
                filter_desired = Some(args[i + 1].clone());
                i += 1;
            }
            "--json" => json_output = true,
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let mut ads = transport.fetch_swap_advertisements(network_str).await?;

    // Apply prefix filters (match on any hex prefix, case-insensitive).
    if let Some(src) = &filter_source {
        let s = src.to_lowercase();
        ads.retain(|a| a.source_ledger.to_lowercase().starts_with(&s));
    }
    if let Some(dst) = &filter_desired {
        let s = dst.to_lowercase();
        ads.retain(|a| {
            a.desired_ledgers.is_empty()
                || a.desired_ledgers
                    .iter()
                    .any(|l| l.to_lowercase().starts_with(&s))
        });
    }

    if json_output {
        for ad in &ads {
            println!("{}", serde_json::to_string(ad)?);
        }
        return Ok(());
    }

    if ads.is_empty() {
        println!("No open swap advertisements found.");
        return Ok(());
    }

    println!("Open Swap Advertisements ({})", ads.len());
    println!("============================");
    for (i, ad) in ads.iter().enumerate() {
        let avail_sats = ad.available_msats / 1000;
        println!();
        println!(
            "{}. {} sats on {}...",
            i + 1,
            avail_sats,
            &ad.source_ledger[..16.min(ad.source_ledger.len())]
        );
        println!("   Maker:   {}...", &ad.maker_pubkey[..16.min(ad.maker_pubkey.len())]);
        println!(
            "   Deposit: {}",
            &ad.source_deposit_id[..16.min(ad.source_deposit_id.len())]
        );
        if ad.desired_ledgers.is_empty() {
            println!("   Wants:   any ledger");
        } else {
            let short: Vec<String> = ad
                .desired_ledgers
                .iter()
                .map(|l| format!("{}...", &l[..8.min(l.len())]))
                .collect();
            println!("   Wants:   {}", short.join(", "));
        }
        if ad.fee_fixed_msats > 0 || ad.fee_rate_bps > 0 {
            println!(
                "   Fee:     {} msats + {} bps",
                ad.fee_fixed_msats, ad.fee_rate_bps
            );
        } else {
            println!("   Fee:     (free)");
        }
        if ad.min_swap_msats > 0 || ad.max_swap_msats > 0 {
            let min_sats = ad.min_swap_msats / 1000;
            let max_str = if ad.max_swap_msats > 0 {
                format!("{} sats", ad.max_swap_msats / 1000)
            } else {
                "no cap".to_string()
            };
            println!("   Limits:  min {} sats, max {}", min_sats, max_str);
        }
        if ad.expires_at > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let remaining_hours = ad.expires_at.saturating_sub(now) / 3600;
            println!("   Expires: in ~{} hour(s)", remaining_hours);
        }
        if let Some(note) = &ad.note {
            println!("   Note:    {}", note);
        }
    }

    Ok(())
}

/// Taker-side: request a swap against a published advertisement.
///
/// Usage: deposits-wallet swap-request <ad_id_prefix> <amount_sats>
///          --from <taker_source_alias>
///          --receive-on <taker_dest_alias>
///          [--timeout-ms <ms>]
///          --relay <url>
///
/// Sends an ephemeral Kind 20103 swap_request to the ad's author, then waits
/// for a Kind 20104 response. This phase only negotiates — the HTLC execution
/// is wired in separately.
pub async fn swap_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    let mut ad_prefix: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut from_alias: Option<String> = None;
    let mut receive_alias: Option<String> = None;
    let mut timeout_ms: u64 = 30_000;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from" if i + 1 < args.len() => {
                from_alias = Some(args[i + 1].clone());
                i += 1;
            }
            "--receive-on" if i + 1 < args.len() => {
                receive_alias = Some(args[i + 1].clone());
                i += 1;
            }
            "--timeout-ms" if i + 1 < args.len() => {
                timeout_ms = args[i + 1].parse()?;
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
                if ad_prefix.is_none() {
                    ad_prefix = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let ad_prefix = ad_prefix.ok_or(
        "Usage: deposits-wallet swap-request <ad_id_prefix> <amount_sats> --from <alias> --receive-on <alias> --relay <url>"
    )?;
    let amount_sats = amount_sats.ok_or("Missing amount_sats")?;
    let from_alias = from_alias.ok_or("Missing --from <alias> (taker's source deposit)")?;
    let receive_alias =
        receive_alias.ok_or("Missing --receive-on <alias> (taker's deposit on maker's ledger)")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    let data = std::fs::read_to_string(&deposits_file)
        .map_err(|_| "No deposits found. Use 'open' to create deposits first.")?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let from_dep = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&from_alias))
        .ok_or_else(|| format!("No deposit '{}' (use --from)", from_alias))?;
    let recv_dep = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&receive_alias))
        .ok_or_else(|| format!("No deposit '{}' (use --receive-on)", receive_alias))?;

    let from_ledger = from_dep["ledger_id"]
        .as_str()
        .ok_or("Invalid 'from' deposit")?
        .to_string();
    let recv_ledger = recv_dep["ledger_id"]
        .as_str()
        .ok_or("Invalid 'receive-on' deposit")?
        .to_string();

    // Connect to relay and fetch swap ads.
    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let ads = transport.fetch_swap_advertisements(network_str).await?;
    let ad_prefix_lower = ad_prefix.to_lowercase();
    let ad = ads
        .iter()
        .find(|a| {
            a.event_id.to_lowercase().starts_with(&ad_prefix_lower)
                || a.source_deposit_id
                    .to_lowercase()
                    .starts_with(&ad_prefix_lower)
        })
        .ok_or_else(|| format!("No swap ad matching '{}'", ad_prefix))?;

    // Sanity: our receive deposit must be on the ad's source ledger (that's
    // where we'll receive from the maker).
    if recv_ledger != ad.source_ledger {
        return Err(format!(
            "--receive-on '{}' is on ledger {}..., but the ad's source ledger is {}...",
            receive_alias,
            &recv_ledger[..16],
            &ad.source_ledger[..16]
        )
        .into());
    }

    // Limits check.
    let amount_msats = amount_sats.saturating_mul(1000);
    if ad.min_swap_msats > 0 && amount_msats < ad.min_swap_msats {
        return Err(format!(
            "Amount below ad minimum: {} < {} msats",
            amount_msats, ad.min_swap_msats
        )
        .into());
    }
    if ad.max_swap_msats > 0 && amount_msats > ad.max_swap_msats {
        return Err(format!(
            "Amount above ad maximum: {} > {} msats",
            amount_msats, ad.max_swap_msats
        )
        .into());
    }
    if amount_msats > ad.available_msats {
        return Err(format!(
            "Amount exceeds ad availability: {} > {} msats",
            amount_msats, ad.available_msats
        )
        .into());
    }

    // Taker's source deposit_id (the right leg).
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let from_key_index = from_dep
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let from_sk = derive_secret_key_at_index(&config.seed, config.network, from_key_index)?;
    let from_pk = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &from_sk).public_key();
    let from_descriptor = format!("pk({})", hex::encode(from_pk.serialize()));
    let from_deposit_id = compute_deposit_id(&from_descriptor);

    // Taker's dest deposit_id on the ad's source ledger (left leg receiver).
    let recv_key_index = recv_dep
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let recv_sk = derive_secret_key_at_index(&config.seed, config.network, recv_key_index)?;
    let recv_pk = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &recv_sk).public_key();
    let recv_descriptor = format!("pk({})", hex::encode(recv_pk.serialize()));
    let recv_deposit_id = compute_deposit_id(&recv_descriptor);

    // Generate preimage + hash (taker keeps preimage).
    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let hash = sha256::Hash::hash(&preimage);

    let req = SwapRequest {
        swap_ad_event_id: ad.event_id.clone(),
        amount_msats,
        hash_hex: hex::encode(hash.as_byte_array()),
        taker_source_ledger: from_ledger.clone(),
        taker_source_deposit_id: hex::encode(from_deposit_id),
        taker_dest_deposit_id: hex::encode(recv_deposit_id),
        relay_url: config.relays[0].clone(),
        event_id: String::new(),
        taker_pubkey: String::new(),
        timestamp: 0,
    };

    println!("Swap Request");
    println!("============");
    println!("  Ad:       {} ({} sats available)", &ad.event_id[..16], ad.available_msats / 1000);
    println!("  Maker:    {}...", &ad.maker_pubkey[..16]);
    println!("  Swap:     {} sats on {}... → {} sats on {}...",
        amount_sats,
        &from_ledger[..12],
        amount_sats,
        &ad.source_ledger[..12]);
    println!("  Preimage: (generated, kept locally)");
    println!("  Hash:     {}...", hex::encode(hash.as_byte_array())[..16].to_string());
    println!();

    // Create the broadcast receiver BEFORE subscribing — receivers only see
    // events sent after their creation, so any response arriving before we
    // call notifications() would be lost.
    let mut rx = transport.create_notification_receiver();
    // Subscribe BEFORE publishing — ephemeral kinds are only delivered while
    // the subscription is live.
    transport.subscribe_swap_responses().await?;

    let req_event_id = transport
        .publish_swap_request(&ad.maker_pubkey, &req)
        .await?;
    println!("Published request: {}", &req_event_id[..16]);
    println!("Waiting for maker response (timeout {}ms)...", timeout_ms);

    let resp = transport
        .wait_for_swap_response(&mut rx, &req_event_id, timeout_ms)
        .await?;

    println!();
    if !resp.accepted {
        println!("REJECTED");
        println!("  Reason: {}", resp.reason.as_deref().unwrap_or("(none)"));
        return Ok(());
    }

    println!("ACCEPTED");
    println!(
        "  Fee: {} msats, timeouts: left +{} / right +{} blocks",
        resp.fee_msats, resp.timeout_left_blocks, resp.timeout_right_blocks
    );
    let maker_dest_hex = resp
        .maker_dest_deposit_id
        .as_deref()
        .ok_or("maker did not supply maker_dest_deposit_id")?;
    let maker_dest_bytes = hex::decode(maker_dest_hex)?;
    if maker_dest_bytes.len() != 16 {
        return Err("maker_dest_deposit_id must be 32 hex chars".into());
    }
    let mut maker_dest_id = [0u8; 16];
    maker_dest_id.copy_from_slice(&maker_dest_bytes);

    // Configure the response filter so subsequent transfer_lock /
    // transfer_complete calls (on both legs) are deliverable.
    configure_swap_response_filter(&transport, &ad.source_ledger, &from_ledger);

    // ── 1/3: wait for maker's lock on the ad's source ledger ──
    println!();
    println!(
        "[1/3] waiting for maker to lock on source ledger ({}...)",
        &ad.source_ledger[..12]
    );
    let left_transfer_id = watch_for_lock(
        &transport,
        &ad.source_ledger,
        &hex::encode(hash.as_byte_array()),
        recv_deposit_id,
        amount_msats,
        120,
    )
    .await?;
    println!("      locked: {}...", &hex::encode(left_transfer_id)[..16]);

    // ── 2/3: lock on our source ledger ──
    println!(
        "[2/3] locking {} sats on our source ledger ({}...)",
        (amount_msats + resp.fee_msats) / 1000,
        &from_ledger[..12]
    );
    let right_amount = amount_msats.saturating_add(resp.fee_msats);
    let right_operator_fee = default_operator_fee(right_amount);
    let right_block = current_block_for(&transport, &from_ledger).await?;
    let right_timeout = right_block.saturating_add(resp.timeout_right_blocks);

    let hash_hex = hex::encode(hash.as_byte_array());
    let completion_script = format!("sha256({})", hash_hex);
    let right_transfer_id = submit_transfer_lock(
        &transport,
        &from_ledger,
        &from_sk,
        from_deposit_id,
        maker_dest_id,
        right_amount,
        right_operator_fee,
        &completion_script,
        right_timeout,
    )
    .await?;
    println!("      locked: {}...", &hex::encode(right_transfer_id)[..16]);

    // ── 3/3: reveal preimage on source ledger, claiming maker's lock ──
    println!(
        "[3/3] revealing preimage on source ledger ({}...)",
        &ad.source_ledger[..12]
    );
    submit_transfer_complete(&transport, &ad.source_ledger, left_transfer_id, preimage).await?;

    println!();
    println!(
        "Swap complete: sent {} sats on {}..., received {} sats on {}....",
        right_amount / 1000,
        &from_ledger[..12],
        amount_msats / 1000,
        &ad.source_ledger[..12]
    );
    println!("(maker will claim right leg using the revealed preimage)");

    Ok(())
}

/// Maker-side: listen for incoming swap requests against our published ads
/// and auto-respond based on ad limits.
///
/// Usage: deposits-wallet swap-listen [--once] --relay <url>
pub async fn swap_listen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut once = false;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--once" => once = true,
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    let data = std::fs::read_to_string(&deposits_file)
        .map_err(|_| "No deposits found.")?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let nostr_key = config.nostr_key()?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let nostr_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &nostr_key);
    // Nostr identifies authors by x-only pubkey (BIP-340) — required for p-tag match.
    let (xonly_pk, _parity) = nostr_pk.x_only_public_key();
    let our_pubkey_hex = hex::encode(xonly_pk.serialize());

    let transport = std::sync::Arc::new(
        NostrTransportBuilder::new(nostr_key)
            .relay(&config.relays[0])
            .build()
            .await?,
    );

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    // Index our ads by event_id for fast lookup on each request.
    let all_ads = transport.fetch_swap_advertisements(network_str).await?;
    let our_ads: Vec<SwapAdvertisement> = all_ads
        .into_iter()
        .filter(|a| a.maker_pubkey == our_pubkey_hex)
        .collect();

    if our_ads.is_empty() {
        return Err("No swap advertisements published from this wallet. Publish one first with swap-advertise.".into());
    }

    let mut rx = transport.create_notification_receiver();
    transport.subscribe_swap_requests(&our_pubkey_hex).await?;

    println!(
        "swap-listen: {} of our ad(s) visible, listening for requests as {}...",
        our_ads.len(),
        &our_pubkey_hex[..16]
    );

    // For --once: short bounded wait. Otherwise: long wait, loop forever.
    let wait_ms: u64 = if once { 30_000 } else { 300_000 };
    loop {
        let maybe_req = transport
            .next_swap_request(&mut rx, wait_ms)
            .await
            .unwrap_or(None);
        if let Some(req) = maybe_req {
            handle_swap_request(&transport, &our_ads, &deposits, &config, &req).await;
            if once {
                break;
            }
        } else if once {
            println!("(no request within {}s)", wait_ms / 1000);
            break;
        }
    }

    Ok(())
}

async fn handle_swap_request(
    transport: &std::sync::Arc<deposits_nostr::NostrTransport>,
    our_ads: &[SwapAdvertisement],
    deposits: &[serde_json::Value],
    config: &super::WalletConfig,
    req: &SwapRequest,
) {
    println!();
    println!("[request {}] from {}...",
        &req.event_id[..16], &req.taker_pubkey[..16]);
    println!("  ad:     {}...", &req.swap_ad_event_id[..16]);
    println!("  amount: {} msats", req.amount_msats);
    println!("  taker source ledger: {}...", &req.taker_source_ledger[..16]);

    let reject = |reason: &str| {
        let resp = SwapResponse {
            request_event_id: req.event_id.clone(),
            accepted: false,
            reason: Some(reason.to_string()),
            maker_dest_deposit_id: None,
            timeout_left_blocks: 0,
            timeout_right_blocks: 0,
            fee_msats: 0,
            event_id: String::new(),
            timestamp: 0,
        };
        (resp, reason.to_string())
    };

    // Match to one of our ads.
    let ad = match our_ads.iter().find(|a| a.event_id == req.swap_ad_event_id) {
        Some(a) => a,
        None => {
            let (resp, msg) = reject("no matching ad (stale or replaced?)");
            println!("  → REJECT: {}", msg);
            let _ = transport
                .publish_swap_response(&req.taker_pubkey, &resp)
                .await;
            return;
        }
    };

    // Limits.
    if ad.min_swap_msats > 0 && req.amount_msats < ad.min_swap_msats {
        let (resp, msg) = reject("amount below ad minimum");
        println!("  → REJECT: {}", msg);
        let _ = transport
            .publish_swap_response(&req.taker_pubkey, &resp)
            .await;
        return;
    }
    if ad.max_swap_msats > 0 && req.amount_msats > ad.max_swap_msats {
        let (resp, msg) = reject("amount above ad maximum");
        println!("  → REJECT: {}", msg);
        let _ = transport
            .publish_swap_response(&req.taker_pubkey, &resp)
            .await;
        return;
    }
    if req.amount_msats > ad.available_msats {
        let (resp, msg) = reject("amount exceeds ad availability");
        println!("  → REJECT: {}", msg);
        let _ = transport
            .publish_swap_response(&req.taker_pubkey, &resp)
            .await;
        return;
    }

    // Find our deposit on taker's source ledger — that's where we receive.
    // Skip the taker's own source deposit (would collapse the swap to a no-op).
    let taker_source_id_hex = req.taker_source_deposit_id.as_str();
    let maker_dest = deposits.iter().find(|d| {
        let ledger_match = d.get("ledger_id").and_then(|v| v.as_str())
            == Some(&req.taker_source_ledger);
        let our_did = crate::wallet_cli::deposit_record_identity(d)
            .map(|(_, id)| id)
            .unwrap_or_default();
        ledger_match && our_did != taker_source_id_hex
    });
    let maker_dest = match maker_dest {
        Some(d) => d,
        None => {
            let (resp, msg) = reject("no deposit on taker's source ledger to receive on");
            println!("  → REJECT: {}", msg);
            let _ = transport
                .publish_swap_response(&req.taker_pubkey, &resp)
                .await;
            return;
        }
    };
    let maker_dest_key_index = maker_dest
        .get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let maker_dest_sk = match derive_secret_key_at_index(
        &config.seed,
        config.network,
        maker_dest_key_index,
    ) {
        Ok(k) => k,
        Err(_) => {
            let (resp, msg) = reject("failed to derive maker dest key");
            println!("  → REJECT: {}", msg);
            let _ = transport
                .publish_swap_response(&req.taker_pubkey, &resp)
                .await;
            return;
        }
    };
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let maker_dest_pk =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &maker_dest_sk).public_key();
    let maker_dest_descriptor = format!("pk({})", hex::encode(maker_dest_pk.serialize()));
    let maker_dest_id = compute_deposit_id(&maker_dest_descriptor);

    // Fee = fixed + amount * rate_bps / 10000
    let fee_msats = ad
        .fee_fixed_msats
        .saturating_add(req.amount_msats.saturating_mul(ad.fee_rate_bps as u64) / 10_000);

    // Timeouts: left leg shorter (maker's lock), right leg longer (taker's).
    // Default: 144 blocks for left, 288 blocks for right (~1 and ~2 days on main;
    // trivially fast on regtest). Safe under the protocol's 1008-block cap.
    let timeout_left_blocks: u32 = 144;
    let timeout_right_blocks: u32 = 288;

    let resp = SwapResponse {
        request_event_id: req.event_id.clone(),
        accepted: true,
        reason: None,
        maker_dest_deposit_id: Some(hex::encode(maker_dest_id)),
        timeout_left_blocks,
        timeout_right_blocks,
        fee_msats,
        event_id: String::new(),
        timestamp: 0,
    };

    match transport
        .publish_swap_response(&req.taker_pubkey, &resp)
        .await
    {
        Ok(rid) => println!(
            "  → ACCEPT (fee {} msats, left +{} / right +{}): response {}",
            fee_msats, timeout_left_blocks, timeout_right_blocks, &rid[..16]
        ),
        Err(e) => {
            println!("  → ACCEPT failed to publish: {}", e);
            return;
        }
    }

    // ── Maker-side HTLC execution ──
    // Run in a spawned task so the listener can keep accepting new requests
    // concurrently.
    let transport = std::sync::Arc::clone(transport);
    let ad = ad.clone();
    let req = req.clone();
    let config = config.clone();
    let maker_source_sk = match derive_ad_source_sk(&ad, deposits, &config) {
        Ok(k) => k,
        Err(e) => {
            println!("  execution error: {}", e);
            return;
        }
    };
    let ad_source_deposit_bytes = match hex::decode(&ad.source_deposit_id) {
        Ok(b) if b.len() == 16 => {
            let mut out = [0u8; 16];
            out.copy_from_slice(&b);
            out
        }
        _ => {
            println!("  execution error: ad.source_deposit_id malformed");
            return;
        }
    };
    let taker_dest_id = match hex::decode(&req.taker_dest_deposit_id) {
        Ok(b) if b.len() == 16 => {
            let mut out = [0u8; 16];
            out.copy_from_slice(&b);
            out
        }
        _ => {
            println!("  execution error: req.taker_dest_deposit_id malformed");
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = execute_maker_swap(
            &transport,
            &ad,
            &req,
            &maker_source_sk,
            ad_source_deposit_bytes,
            taker_dest_id,
            maker_dest_id,
            timeout_left_blocks,
            fee_msats,
        )
        .await
        {
            println!("  maker execution failed ({}...): {}", &req.event_id[..16], e);
        } else {
            println!("  swap {} completed on maker side", &req.event_id[..16]);
        }
    });
}

/// Look up the maker's source deposit secret key from `deposits.json` by
/// matching against `ad.source_deposit_id`.
fn derive_ad_source_sk(
    ad: &SwapAdvertisement,
    deposits: &[serde_json::Value],
    config: &super::WalletConfig,
) -> Result<bitcoin::secp256k1::SecretKey, Box<dyn std::error::Error + Send + Sync>> {
    let target_bytes = hex::decode(&ad.source_deposit_id)
        .map_err(|e| format!("bad source_deposit_id hex: {}", e))?;
    if target_bytes.len() != 16 {
        return Err("source_deposit_id must be 32 hex chars".into());
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&target_bytes);

    let dep = find_deposit_by_id(deposits, config, target)
        .ok_or("maker's source deposit not found in wallet deposits.json")?;
    let key_index = dep.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    derive_secret_key_at_index(&config.seed, config.network, key_index)
        .map_err(|e| format!("key derivation: {}", e).into())
}

#[allow(clippy::too_many_arguments)]
async fn execute_maker_swap(
    transport: &deposits_nostr::NostrTransport,
    ad: &SwapAdvertisement,
    req: &SwapRequest,
    maker_source_sk: &bitcoin::secp256k1::SecretKey,
    maker_source_deposit_id: [u8; 16],
    taker_dest_deposit_id: [u8; 16],
    maker_dest_deposit_id: [u8; 16],
    timeout_left_blocks: u32,
    _fee_msats: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let completion_script = format!("sha256({})", req.hash_hex);

    // Configure the response filter up-front to cover both legs.
    configure_swap_response_filter(transport, &ad.source_ledger, &req.taker_source_ledger);

    // ── 1/4: lock on LEFT (our source ledger) ──
    let left_block = current_block_for(transport, &ad.source_ledger)
        .await
        .map_err(|e| format!("fetch left block: {}", e))?;
    let left_timeout = left_block.saturating_add(timeout_left_blocks);
    let left_operator_fee = default_operator_fee(req.amount_msats);

    let left_transfer_id = submit_transfer_lock(
        transport,
        &ad.source_ledger,
        maker_source_sk,
        maker_source_deposit_id,
        taker_dest_deposit_id,
        req.amount_msats,
        left_operator_fee,
        &completion_script,
        left_timeout,
    )
    .await
    .map_err(|e| format!("lock left: {}", e))?;
    println!(
        "  [{}...] maker locked left leg {} sats, tx {}...",
        &req.event_id[..16],
        req.amount_msats / 1000,
        &hex::encode(left_transfer_id)[..16]
    );

    // ── 2/4: wait for taker's lock on RIGHT ──
    let right_amount = req.amount_msats.saturating_add(_fee_msats);
    let right_transfer_id = watch_for_lock(
        transport,
        &req.taker_source_ledger,
        &req.hash_hex,
        maker_dest_deposit_id,
        right_amount,
        180,
    )
    .await
    .map_err(|e| format!("watch right lock: {}", e))?;
    println!(
        "  [{}...] taker locked right leg {} sats, tx {}...",
        &req.event_id[..16],
        right_amount / 1000,
        &hex::encode(right_transfer_id)[..16]
    );

    // ── 3/4: wait for taker to reveal preimage on LEFT ──
    let preimage = watch_for_reveal(transport, &ad.source_ledger, left_transfer_id, 180)
        .await
        .map_err(|e| format!("watch left reveal: {}", e))?;
    println!(
        "  [{}...] taker revealed preimage, claiming right leg",
        &req.event_id[..16]
    );

    // ── 4/4: claim right leg using the revealed preimage ──
    submit_transfer_complete(
        transport,
        &req.taker_source_ledger,
        right_transfer_id,
        preimage,
    )
    .await
    .map_err(|e| format!("complete right: {}", e))?;
    Ok(())
}
