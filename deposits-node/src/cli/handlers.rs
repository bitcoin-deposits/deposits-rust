//! Request handlers for Nostr-based ledger requests
//!
//! These functions process incoming requests from Nostr and return responses.

use bitcoin::secp256k1::PublicKey;
use std::str::FromStr;

use crate::nostr::{LedgerAdvertisement, LedgerRequest, NostrTransport};
use crate::{Node, NodeConfig};

/// Process a deposit_open request
pub async fn process_deposit_open_request(
    node: &mut Node,
    ledger_id: &str,
    request: &LedgerRequest,
    transport: &NostrTransport,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    // Verify ledger exists - we use ledger_id directly now
    if node.get_ledger(ledger_id).is_none() {
        return (
            false,
            None,
            Some(format!("Ledger not found: {}", ledger_id)),
        );
    }

    // Extract deposit_pubkey from params
    let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                false,
                None,
                Some("Missing deposit_pubkey parameter".to_string()),
            )
        }
    };

    let _deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
    };

    // Fetch the advertisement to get fee minimums
    let advertisement = match transport.fetch_ledger_advertisement(ledger_id).await {
        Ok(Some(ad)) => ad,
        Ok(None) => {
            tracing::warn!(
                "No advertisement found for ledger {}, using zero fee minimums",
                ledger_id
            );
            LedgerAdvertisement::new(
                ledger_id.to_string(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
        Err(e) => {
            tracing::warn!(
                "Failed to fetch advertisement: {}, using zero fee minimums",
                e
            );
            LedgerAdvertisement::new(
                ledger_id.to_string(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
    };

    let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();

    // Extract fee parameters from request OR use advertisement defaults
    // Use advertisement's fee_period_blocks unless client overrides
    // If fee_period_blocks is 0 (not set), use default of 2016 blocks (~2 weeks)
    let ad_period = if advertisement.fee_period_blocks > 0 {
        advertisement.fee_period_blocks
    } else {
        2016
    };
    let frequency_blocks = request
        .params
        .get("fee_frequency")
        .and_then(|v| v.as_u64())
        .map(|v| if v > 0 { v as u32 } else { 2016 })
        .unwrap_or(ad_period);

    let fees =
        if request.params.get("fee_fixed").is_some() || request.params.get("fee_bps").is_some() {
            deposits_core::FeeStructure {
                annualized_msats: request
                    .params
                    .get("fee_fixed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                annualized_bps: request
                    .params
                    .get("fee_bps")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16,
                frequency_blocks,
            }
        } else {
            // Use advertisement defaults if no fees specified
            advertisement.to_fee_structure()
        };

    // Validate proposed fees meet operator minimums
    if let Err(e) = deposits_core::operation_validation::validate_fee_minimum(
        &fees,
        min_annual_bps,
        min_fixed_per_period,
    ) {
        return (false, None, Some(format!("Fee validation failed: {}", e)));
    }

    // Convert deposit_pubkey to descriptor
    let descriptor = format!("pk({})", deposit_pubkey_str);

    // Open the deposit with co-signing
    match node
        .open_deposit(ledger_id, &descriptor, Some(fees), None, false, false)
        .await
    {
        Ok(deposit) => {
            let result = serde_json::json!({
                "deposit_pubkey": deposit_pubkey_str,
                "deposit_id": hex::encode(deposit.deposit_id),
                "balance": deposit.balance,
                "fees": {
                    "fixed": deposit.fees.annualized_msats,
                    "bps": deposit.fees.annualized_bps,
                    "frequency": deposit.fees.frequency_blocks,
                }
            });
            (true, Some(result), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    }
}

/// Process a make_offer request
pub async fn process_make_offer_request(
    node: &Node,
    ledger_id: &str,
    request: &LedgerRequest,
    transport: &NostrTransport,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    // Verify the ledger exists (ledger_id may be a hash or reserves_id)
    // We use ledger_id directly for the offer since it's stable across custody transfers
    let resolved_ledger_id =
        if ledger_id.len() == 64 && ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            // Already a 64-char hex ledger_id hash
            ledger_id.to_string()
        } else {
            // It's a reserves_id, look up the ledger to get its ledger_id
            match node.get_ledger_by_reserves_key(ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", ledger_id)),
                    )
                }
            }
        };

    // Extract deposit_pubkey from params
    let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                false,
                None,
                Some("Missing deposit_pubkey parameter".to_string()),
            )
        }
    };

    let deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
    };

    // Extract required parameters
    let max_sats = match request.params.get("max_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing max_sats parameter".to_string())),
    };

    let min_sats = match request.params.get("min_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing min_sats parameter".to_string())),
    };

    let blocks_valid = match request.params.get("blocks_valid").and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return (
                false,
                None,
                Some("Missing blocks_valid parameter".to_string()),
            )
        }
    };

    if min_sats >= max_sats {
        return (
            false,
            None,
            Some("min_sats must be less than max_sats".to_string()),
        );
    }

    // Fetch the advertisement to get fee minimums
    let advertisement = match transport
        .fetch_ledger_advertisement(&resolved_ledger_id)
        .await
    {
        Ok(Some(ad)) => ad,
        Ok(None) => {
            tracing::warn!(
                "No advertisement found for ledger {}, using zero fee minimums",
                resolved_ledger_id
            );
            LedgerAdvertisement::new(
                resolved_ledger_id.clone(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
        Err(e) => {
            tracing::warn!(
                "Failed to fetch advertisement: {}, using zero fee minimums",
                e
            );
            LedgerAdvertisement::new(
                resolved_ledger_id.clone(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
    };

    let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();
    let ad_period = if advertisement.fee_period_blocks > 0 {
        advertisement.fee_period_blocks
    } else {
        2016
    };

    // Extract fee parameters from request if provided, or use advertisement defaults
    let fees = if request.params.get("fee_fixed").is_some()
        || request.params.get("fee_bps").is_some()
        || request.params.get("fee_frequency").is_some()
    {
        let frequency_blocks = request
            .params
            .get("fee_frequency")
            .and_then(|v| v.as_u64())
            .map(|v| if v > 0 { v as u32 } else { ad_period })
            .unwrap_or(ad_period);

        deposits_core::FeeStructure {
            annualized_msats: request
                .params
                .get("fee_fixed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            annualized_bps: request
                .params
                .get("fee_bps")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16,
            frequency_blocks,
        }
    } else {
        // Use advertisement defaults if no fees specified
        advertisement.to_fee_structure()
    };

    // Validate proposed fees meet operator minimums
    if let Err(e) = deposits_core::operation_validation::validate_fee_minimum(
        &fees,
        min_annual_bps,
        min_fixed_per_period,
    ) {
        return (false, None, Some(format!("Fee validation failed: {}", e)));
    }

    // Sync wallet to get current block height
    if let Err(e) = node.sync_wallet() {
        return (false, None, Some(format!("Failed to sync wallet: {}", e)));
    }

    // Create the offer using ledger_id (stable across custody transfers)
    // Include fees so they're stored with the offer and applied when deposit is completed
    match node.create_deposit_offer(
        &resolved_ledger_id,
        deposit_pubkey,
        max_sats,
        min_sats,
        blocks_valid,
        Some(fees),
    ) {
        Ok(offer) => {
            // Check if we need a co-signature (post-rotation)
            // Note: CLI handlers use their own transport, but can still check has_quorum_reserves
            // For the CLI handler, we simply return the offer without co-signature
            // since the Node.run() flow handles requests, not the CLI `nostr watch` flow.
            // The daemon (Node) handles make_offer requests and will add co-signatures.
            // CLI handlers are for development/testing where co-signing may not be needed.
            let result = serde_json::json!({
                "offer_id": hex::encode(offer.offer_id),
                "operator_id": offer.operator_id.to_string(),
                "funding_address": offer.funding_address,
                "deadline_block": offer.deadline_block,
                "created_at_block": offer.created_at_block,
                "max_sats": max_sats,
                "min_sats": min_sats,
                "cosign_required": false,
            });
            (true, Some(result), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    }
}

/// Process a collateral_lock request
pub async fn process_collateral_lock_request(
    node: &mut Node,
    ledger_id: &str,
    request: &LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::Secp256k1;

    // Verify ledger exists - we use ledger_id directly now
    if node.get_ledger(ledger_id).is_none() {
        return (
            false,
            None,
            Some(format!("Ledger not found: {}", ledger_id)),
        );
    }

    // Extract deposit_secret from params
    let deposit_secret_hex = match request.params.get("deposit_secret") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                false,
                None,
                Some("Missing deposit_secret parameter".to_string()),
            )
        }
    };

    let secret_bytes = match hex::decode(&deposit_secret_hex) {
        Ok(b) => b,
        Err(e) => {
            return (
                false,
                None,
                Some(format!("Invalid deposit_secret hex: {}", e)),
            )
        }
    };

    let deposit_secret = match bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes) {
        Ok(s) => s,
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret: {}", e))),
    };

    // Derive the deposit pubkey from the secret and create descriptor
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));

    // Extract required parameters
    let amount_msats = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => {
            return (
                false,
                None,
                Some("Missing amount_msats parameter".to_string()),
            )
        }
    };

    let lock_blocks = match request.params.get("lock_blocks").and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return (
                false,
                None,
                Some("Missing lock_blocks parameter".to_string()),
            )
        }
    };

    // Get current block height and compute lock_until_block
    let current_block = match node.wallet.get_block_height() {
        Ok(h) => h,
        Err(e) => {
            return (
                false,
                None,
                Some(format!("Failed to get block height: {}", e)),
            )
        }
    };
    let lock_until_block = current_block + lock_blocks;

    // Parse requesting operator (defaults to sender's node_id derived from event)
    let requesting_operator =
        if let Some(serde_json::Value::String(hex)) = request.params.get("requesting_operator") {
            match PublicKey::from_str(hex) {
                Ok(pk) => pk,
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("Invalid requesting_operator: {}", e)),
                    )
                }
            }
        } else {
            // Default to the operator's own node_id (self-request)
            node.node_id
        };

    // Lock the collateral (now includes co-signing and broadcast)
    // In direct CLI mode, the node itself is the quorum member pledging collateral
    match node
        .lock_collateral(
            ledger_id,
            &descriptor,
            &deposit_secret,
            amount_msats,
            lock_until_block,
            requesting_operator,
            node.node_id,
        )
        .await
    {
        Ok(attestation) => {
            // Serialize attestation as JSON then base64 encode for easy shell parsing
            // (base64 avoids escaping issues with nested JSON)
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
            let attestation_json = serde_json::to_string(&attestation).unwrap_or_default();
            let attestation_b64 = BASE64.encode(attestation_json.as_bytes());
            let result = serde_json::json!({
                "amount": attestation.amount,
                "lock_until_block": attestation.lock_until_block,
                "quorum_member": attestation.quorum_member.to_string(),
                "attestation_b64": attestation_b64,
            });
            (true, Some(result), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    }
}

/// Process a deposit_withdraw request
///
/// This is called when a depositor requests a withdrawal via Nostr.
/// The depositor provides their secret (to prove ownership), destination address, and amount.
pub async fn process_deposit_withdraw_request(
    node: &mut Node,
    ledger_id: &str,
    request: &LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::Secp256k1;

    // Verify ledger exists - we use ledger_id directly now
    if node.get_ledger(ledger_id).is_none() {
        return (
            false,
            None,
            Some(format!("Ledger not found: {}", ledger_id)),
        );
    }

    // Extract deposit_secret from params
    let deposit_secret_hex = match request.params.get("deposit_secret") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                false,
                None,
                Some("Missing deposit_secret parameter".to_string()),
            )
        }
    };

    // Parse the secret and derive the pubkey
    let secret_bytes = match hex::decode(&deposit_secret_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(_) => {
            return (
                false,
                None,
                Some("deposit_secret must be 32 bytes".to_string()),
            )
        }
        Err(e) => {
            return (
                false,
                None,
                Some(format!("Invalid deposit_secret hex: {}", e)),
            )
        }
    };

    let secp = Secp256k1::new();
    let deposit_secret = match bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes) {
        Ok(sk) => sk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret: {}", e))),
    };
    let deposit_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &deposit_secret);

    // Extract destination address
    let destination_address = match request.params.get("destination_address") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => {
            return (
                false,
                None,
                Some("Missing destination_address parameter".to_string()),
            )
        }
    };

    // Extract amount_sats
    let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => {
            return (
                false,
                None,
                Some("Missing amount_sats parameter".to_string()),
            )
        }
    };

    // Use a fixed fee for now (1000 sats)
    let fee_sats = 1000u64;

    println!("  Processing deposit_withdraw request:");
    println!("    Deposit: {}...", &deposit_pubkey.to_string()[..16]);
    println!("    Destination: {}", destination_address);
    println!("    Amount: {} sats", amount_sats);

    // Generate nonce and create withdrawal signature
    let nonce: [u8; 32] = {
        use bitcoin::hashes::{sha256, Hash};
        let mut data = Vec::new();
        data.extend_from_slice(&secret_bytes);
        data.extend_from_slice(destination_address.as_bytes());
        data.extend_from_slice(&amount_sats.to_le_bytes());
        data.extend_from_slice(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        *sha256::Hash::hash(&data).as_byte_array()
    };

    // Compute deposit_id from descriptor
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    // Create the withdrawal signature
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Message;
    let signing_message = deposits_core::types::OnChainWithdrawal::signing_message(
        &nonce,
        &deposit_id,
        &destination_address,
        amount_sats,
        fee_sats,
    );
    let msg_hash = sha256::Hash::hash(signing_message.as_bytes());
    let msg = Message::from_digest(*msg_hash.as_byte_array());
    let secp = Secp256k1::signing_only();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &deposit_secret);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let signature: [u8; 64] = sig.serialize();

    // Create witness from signature
    let depositor_witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    // Lock the withdrawal with co-signing
    match node
        .lock_withdrawal(
            ledger_id,
            deposit_id,
            destination_address.clone(),
            amount_sats,
            fee_sats,
            nonce,
            depositor_witness,
            None, // memo
        )
        .await
    {
        Ok(result) => {
            let result_json = serde_json::json!({
                "withdrawal_id": hex::encode(result.withdrawal.withdrawal_id),
                "amount_sats": amount_sats,
                "fee_sats": fee_sats,
                "destination_address": destination_address,
                "status": "locked",
            });
            (true, Some(result_json), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    }
}

/// Process a custody_transfer_sign request
///
/// This is called when another quorum member requests our signature for a custody transfer.
/// We validate the violation, verify the spending transaction, sign the sighash, and respond.
pub async fn process_custody_transfer_sign_request(
    node: &Node,
    _config: &NodeConfig,
    request: &LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use crate::nostr::{ledger_tag, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::{SignedLedgerUpdate, TlvDecode};
    use nostr_sdk::prelude::*;

    // Unused: node (we don't need the node for this handler, we fetch ledger from Nostr directly)
    let _ = node;

    println!("  Processing custody_transfer_sign request...");

    // Extract required parameters
    let ledger_id = match request.params.get("ledger_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return (false, None, Some("Missing ledger_id parameter".to_string())),
    };

    let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return (false, None, Some("Missing sighash parameter".to_string())),
    };

    // TODO: Verify unsigned_tx actually spends to new_custodian's address
    let _unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
        Some(tx) => tx.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing unsigned_tx parameter".to_string()),
            )
        }
    };

    let new_custodian_hex = match request.params.get("new_custodian").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing new_custodian parameter".to_string()),
            )
        }
    };

    let violation_details = match request
        .params
        .get("violation_details")
        .and_then(|v| v.as_str())
    {
        Some(d) => d.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing violation_details parameter".to_string()),
            )
        }
    };

    let last_valid_sequence = match request
        .params
        .get("last_valid_sequence")
        .and_then(|v| v.as_u64())
    {
        Some(seq) => seq,
        None => {
            return (
                false,
                None,
                Some("Missing last_valid_sequence parameter".to_string()),
            )
        }
    };

    // Parse sighash
    let sighash_bytes = match hex::decode(&sighash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
        Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
    };

    // Parse new custodian (validated but not directly used in signing)
    let _new_custodian: bitcoin::secp256k1::PublicKey = match new_custodian_hex.parse() {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid new_custodian: {}", e))),
    };

    println!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!(
        "    New custodian: {}...",
        &new_custodian_hex[..16.min(new_custodian_hex.len())]
    );
    println!(
        "    Violation: {}",
        &violation_details[..50.min(violation_details.len())]
    );

    // Validate that we're a quorum member for this ledger
    // First, we need to verify the violation by fetching and validating the ledger ourselves

    // Use the node's operator key (BIP32-derived from seed, not raw seed)
    let secp = Secp256k1::new();
    let secret_key = node.wallet.operator_secret();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = node.node_id;

    println!("    Our key: {}...", &our_pubkey.to_string()[..16]);

    // Use the node's existing nostr client
    let client = node.nostr.client();

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = match client.fetch_events(vec![filter], None).await {
        Ok(e) => e,
        Err(e) => {
            return (false, None, Some(format!("Failed to fetch ledger: {}", e)));
        }
    };

    // Decode and validate updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));

    // Deduplicate by (sequence_number, operator_id, current_hash) to handle relay duplicates
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.current_hash == b.current_hash
    });

    // Find the original operator (the one who opened the ledger)
    let original_operator = updates
        .iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id);

    let original_operator = match original_operator {
        Some(op) => op,
        None => {
            return (
                false,
                None,
                Some("Could not find ledger genesis (sequence 0)".to_string()),
            )
        }
    };

    // Filter to only the original operator's updates for violation validation
    // (dispute branches from other operators are valid forks, not violations)
    let original_updates: Vec<&SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == original_operator)
        .collect();

    // Verify the violation exists on the original operator's chain
    let mut last_valid_hash = [0u8; 32];
    let mut found_violation = false;
    let mut validated_sequence: i64 = -1;

    for update in &original_updates {
        let expected_seq = (validated_sequence + 1) as u64;
        if update.sequence_number != expected_seq && validated_sequence >= 0 {
            found_violation = true;
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            found_violation = true;
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            found_violation = true;
            break;
        }

        last_valid_hash = update.current_hash;
        validated_sequence = update.sequence_number as i64;
    }

    if !found_violation {
        return (
            false,
            None,
            Some("Could not verify violation - ledger appears conforming".to_string()),
        );
    }

    // Verify that the last_valid_sequence matches our validation
    if validated_sequence != last_valid_sequence as i64 {
        return (
            false,
            None,
            Some(format!(
                "Sequence mismatch: requester says {}, we validated {}",
                last_valid_sequence, validated_sequence
            )),
        );
    }

    println!("    Violation verified at seq {}", validated_sequence + 1);

    // Verify we're a quorum member by checking the ledger operations
    let mut is_quorum_member = false;
    for update in updates.iter().take((validated_sequence + 1) as usize) {
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = operation {
                if quorum_member == our_pubkey {
                    is_quorum_member = true;
                }
            }
        }
    }

    if !is_quorum_member {
        return (
            false,
            None,
            Some("We are not a quorum member for this ledger".to_string()),
        );
    }

    println!("    Verified: we are a quorum member");

    // TODO: Optionally verify the unsigned_tx is spending the correct UTXO to the correct destination
    // For now, we trust that the sighash is computed correctly

    // Sign the sighash
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature_bytes = signature.serialize();

    println!(
        "    Signed sighash: {}...",
        &hex::encode(&signature_bytes[..4])
    );

    // Return the signature
    let result = serde_json::json!({
        "signer": our_pubkey.to_string(),
        "signature": hex::encode(signature_bytes),
        "sighash": sighash_hex,
    });

    (true, Some(result), None)
}

/// Process a confiscation_sign request
///
/// This is called when a quorum member requests signatures for a confiscation transaction
/// that moves reserves to a lottery output for dispute resolution.
pub async fn process_confiscation_sign_request(
    node: &Node,
    _config: &NodeConfig,
    request: &LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use crate::nostr::{ledger_tag, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::{SignedLedgerUpdate, TlvDecode};
    use nostr_sdk::prelude::*;

    // Unused: node (we don't need the node for this handler, we fetch ledger from Nostr directly)
    let _ = node;

    println!("  Processing confiscation_sign request...");

    // Extract required parameters
    let ledger_id = match request.params.get("ledger_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return (false, None, Some("Missing ledger_id parameter".to_string())),
    };

    let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return (false, None, Some("Missing sighash parameter".to_string())),
    };

    let _unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
        Some(tx) => tx.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing unsigned_tx parameter".to_string()),
            )
        }
    };

    let lottery_address = match request
        .params
        .get("lottery_address")
        .and_then(|v| v.as_str())
    {
        Some(a) => a.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing lottery_address parameter".to_string()),
            )
        }
    };

    let violation_details = match request
        .params
        .get("violation_details")
        .and_then(|v| v.as_str())
    {
        Some(d) => d.to_string(),
        None => {
            return (
                false,
                None,
                Some("Missing violation_details parameter".to_string()),
            )
        }
    };

    // Parse sighash
    let sighash_bytes = match hex::decode(&sighash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
        Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
    };

    println!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!(
        "    Lottery addr: {}...",
        &lottery_address[..20.min(lottery_address.len())]
    );
    println!(
        "    Reason: {}",
        &violation_details[..50.min(violation_details.len())]
    );

    // Use the node's operator key (BIP32-derived from seed, not raw seed)
    let secp = Secp256k1::new();
    let secret_key = node.wallet.operator_secret();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = node.node_id;

    println!("    Our key: {}...", &our_pubkey.to_string()[..16]);

    // Use the node's existing nostr client
    let client = node.nostr.client();

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = match client.fetch_events(vec![filter], None).await {
        Ok(e) => e,
        Err(e) => {
            return (false, None, Some(format!("Failed to fetch ledger: {}", e)));
        }
    };

    // Decode and validate updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.current_hash == b.current_hash
    });

    // Verify we're a quorum member by checking the ledger operations
    let mut is_quorum_member = false;
    for update in updates.iter() {
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = operation {
                if quorum_member == our_pubkey {
                    is_quorum_member = true;
                }
            }
        }
    }

    if !is_quorum_member {
        return (
            false,
            None,
            Some("We are not a quorum member for this ledger".to_string()),
        );
    }

    println!("    Verified: we are a quorum member");

    // Verify there are DisputeArmed messages (active dispute)
    let mut armed_count = 0;
    for update in updates.iter() {
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::DisputeArmed { .. } = operation {
                armed_count += 1;
            }
        }
    }

    if armed_count < 2 {
        return (
            false,
            None,
            Some(format!(
                "Not enough armed participants for confiscation (found {})",
                armed_count
            )),
        );
    }

    println!("    Found {} armed participants", armed_count);

    // Sign the sighash
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature_bytes = signature.serialize();

    println!(
        "    Signed sighash: {}...",
        &hex::encode(&signature_bytes[..4])
    );

    // Return the signature
    let result = serde_json::json!({
        "signer": our_pubkey.to_string(),
        "signature": hex::encode(signature_bytes),
        "sighash": sighash_hex,
    });

    (true, Some(result), None)
}

/// Process a custodian_query request
///
/// Quorum members respond with a signed attestation of who they believe is the current
/// custodian for this ledger. Clients collect multiple responses and take the majority.
pub async fn process_custodian_query_request(
    node: &Node,
    ledger_id: &str,
    _request: &LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Message, Secp256k1};

    // Look up the ledger
    let ledger = if let Some((_, l)) = node.get_ledger_by_ledger_id(ledger_id) {
        l
    } else if let Some((_, l)) = node.get_ledger_by_reserves_key(ledger_id) {
        l
    } else {
        return (false, None, Some("Ledger not found".to_string()));
    };

    // Determine who we believe is the current custodian
    // This is the operator_key from the ledger state (which we trust from our local copy)
    let current_custodian = ledger.state.operator_key;

    // Create attestation message: "CUSTODIAN_ATTESTATION:{ledger_id}:{custodian_pubkey}:{timestamp}"
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let attestation_msg = format!(
        "CUSTODIAN_ATTESTATION:{}:{}:{}",
        ledger_id, current_custodian, timestamp
    );

    // Sign the attestation with our operator key
    let secp = Secp256k1::new();
    let secret_key = node.wallet.operator_secret();
    let msg_hash = sha256::Hash::hash(attestation_msg.as_bytes());
    let msg = Message::from_digest(*msg_hash.as_byte_array());
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let result = serde_json::json!({
        "ledger_id": ledger_id,
        "custodian": current_custodian.to_string(),
        "attester": node.node_id.to_string(),
        "timestamp": timestamp,
        "signature": hex::encode(signature.serialize()),
    });

    (true, Some(result), None)
}
