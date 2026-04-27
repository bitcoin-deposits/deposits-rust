//! DEP-12 escalation CLI: ask a quorum member to embed an
//! unprocessed request hash on their own ledger.
//!
//! When the operator ignores a wallet's signed request, the wallet
//! pays a quorum member to record `DeliveryEmbed { request_hash,
//! target_ledger_id, target_operator }` on the member's ledger. The
//! embed becomes part of the member's ledger history; once the
//! operator co-signs a subsequent member-ledger update, their
//! `member_ledger_hash` causally references the embed, proving the
//! operator has seen the request hash. From that point the
//! `service_response_blocks` clock runs.
//!
//! Usage:
//!     deposits-wallet escalate \
//!         --member-ledger <member_ledger_id_hex> \
//!         --request-hash <32-byte hex> \
//!         --target-ledger <operator_ledger_id_hex> \
//!         --target-operator <33-byte pubkey hex> \
//!         --relay <ws://...>
//!
//! The `--member-ledger` is one of the operator's quorum members'
//! ledger ids — pick whichever member you want to pay for the embed.
//! Pricing/payment is intentionally out of scope here today; the
//! member's node accepts the embed unconditionally. A future
//! iteration adds a `payment_commitment` parameter (e.g., a signed
//! `TransferLock` from the wallet's deposit on the member's ledger).

use super::{parse_config, NostrTransportBuilder};

pub async fn escalate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut member_ledger: Option<String> = None;
    let mut request_hash_hex: Option<String> = None;
    let mut target_ledger: Option<String> = None;
    let mut target_operator: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--member-ledger" if i + 1 < args.len() => {
                member_ledger = Some(args[i + 1].clone());
                i += 1;
            }
            "--request-hash" if i + 1 < args.len() => {
                request_hash_hex = Some(args[i + 1].clone());
                i += 1;
            }
            "--target-ledger" if i + 1 < args.len() => {
                target_ledger = Some(args[i + 1].clone());
                i += 1;
            }
            "--target-operator" if i + 1 < args.len() => {
                target_operator = Some(args[i + 1].clone());
                i += 1;
            }
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

    let member_ledger = member_ledger
        .ok_or("Missing --member-ledger <hex>: the quorum member's ledger id where the embed should land")?;
    let request_hash_hex = request_hash_hex
        .ok_or("Missing --request-hash <hex>: 32-byte SHA256 of the original signed request payload")?;
    let target_ledger = target_ledger
        .ok_or("Missing --target-ledger <hex>: the operator's ledger id where the request should have been processed")?;
    let target_operator = target_operator
        .ok_or("Missing --target-operator <hex>: the operator's 33-byte compressed pubkey")?;

    // Sanity-check hex inputs early so the wallet doesn't pay relay
    // round-trip for a malformed request.
    if hex::decode(&request_hash_hex).map(|b| b.len() != 32).unwrap_or(true) {
        return Err("--request-hash must be 32 bytes (64 hex chars)".into());
    }
    if hex::decode(&target_ledger).map(|b| b.len() != 32).unwrap_or(true) {
        return Err("--target-ledger must be 32 bytes (64 hex chars)".into());
    }
    if hex::decode(&target_operator).map(|b| b.len() != 33).unwrap_or(true) {
        return Err("--target-operator must be 33 bytes (66 hex chars, compressed pubkey)".into());
    }

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret = super::derive_secret_key(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret).relay(&relay_url).build().await?;

    println!(
        "Sending delivery_embed request to member {}...",
        &member_ledger[..16.min(member_ledger.len())]
    );

    let params = serde_json::json!({
        "request_hash": request_hash_hex,
        "target_ledger_id": target_ledger,
        "target_operator": target_operator,
    });

    let request_id = transport
        .send_ledger_request(&member_ledger, "delivery_embed", params)
        .await?;
    println!("  Request id: {}...", &request_id[..16]);
    println!("Waiting for member response...");

    match transport.wait_for_response(&request_id, 30_000).await {
        Ok(response) => {
            if response.success {
                let result = response.result.as_ref();
                let event_id = result
                    .and_then(|r| r.get("event_id").and_then(|v| v.as_str()))
                    .unwrap_or("(none)");
                let sequence = result
                    .and_then(|r| r.get("sequence").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                let tip_hash = result
                    .and_then(|r| r.get("tip_hash").and_then(|v| v.as_str()))
                    .unwrap_or("");
                println!();
                println!("Embed committed on member ledger:");
                println!("  Event id:  {}...", &event_id[..16.min(event_id.len())]);
                println!("  Sequence:  {}", sequence);
                if !tip_hash.is_empty() {
                    println!("  Tip hash:  {}...", &tip_hash[..16.min(tip_hash.len())]);
                }
                println!();
                println!("The operator's next co-signature on this member's ledger will causally");
                println!("reference the embed. From that point the service_response_blocks clock");
                println!("runs against the operator on the target ledger.");
                Ok(())
            } else {
                let error = response.error.as_deref().unwrap_or("(no error message)");
                Err(format!("Member rejected delivery_embed: {}", error).into())
            }
        }
        Err(e) => Err(format!("No response from member: {}", e).into()),
    }
}
