//! Deposits request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    pub(crate) async fn process_deposit_open_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing deposit_open request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Resolve DEP-04 subkey delegation. If the request carries v+va
        // tags with a valid attestation AND the sender is on the
        // account's Kind 10301 inbox list, access-control checks run
        // against the account pubkey rather than the delegated signer.
        // An invalid/revoked delegation rejects here with a clean code.
        let effective_sender = match self.resolve_attested_sender(request).await {
            Ok(s) => s,
            Err(why) => {
                tracing::warn!("Deposit open rejected (subkey delegation): {}", why);
                return (
                    false,
                    Some(
                        serde_json::json!({
                            "code": "invalid_subkey_delegation",
                            "detail": why,
                        })
                        .to_string(),
                    ),
                    Some("Invalid or revoked subkey delegation".to_string()),
                );
            }
        };

        // Deposit access control: denylist → (if enabled) npub allowlist → attestation + domain
        //
        // All RwLock guards are dropped before any .await to keep the future Send.
        {
            // Denylist is always checked, even when access control is off.
            // Check BOTH the effective sender (account) and the raw signer
            // so a denied account can't route around via an attested
            // subkey, and a denied subkey stays denied even when attested.
            let denied_account = self
                .deposit_denylist
                .read()
                .unwrap()
                .contains(&effective_sender);
            let denied_signer = self
                .deposit_denylist
                .read()
                .unwrap()
                .contains(&request.sender);
            if denied_account || denied_signer {
                tracing::warn!(
                    "Deposit open rejected: sender {} (effective {}) is on denylist",
                    &request.sender[..16.min(request.sender.len())],
                    &effective_sender[..16.min(effective_sender.len())]
                );
                return (
                    false,
                    Some(serde_json::json!({"code": "denied"}).to_string()),
                    Some("Not authorized to open deposits on this ledger".to_string()),
                );
            }

            if self.deposit_access_control {
                // Snapshot all three lists up front so we can drop the
                // RwLock guards before any .await (the future has to be
                // Send across the attestation query).
                let allowlist: std::collections::HashSet<String> =
                    self.deposit_allowlist.read().unwrap().clone();
                let domains: std::collections::HashSet<String> =
                    self.deposit_domain_allowlist.read().unwrap().clone();

                let on_allowlist = allowlist.contains(&effective_sender);

                if on_allowlist {
                    // Explicitly allowed
                } else {
                    // Look for a lightning-verify attestation that
                    // authorizes this sender. `check_attestation`
                    // tries three paths:
                    //   - lightning_address whose domain is in `domains`
                    //   - allowlist_npub that's in `allowlist` (proclaim)
                    //   - method = "ringsig" (anonymity-set membership;
                    //     no further allowlist matching, the verifier's
                    //     signature is the authorization)
                    // All three need a configured verifier — without
                    // one, no attestation can be trusted. Empty domain
                    // and pubkey allowlists are fine; the ringsig path
                    // doesn't depend on either.
                    let attestation_possible =
                        self.attestation_verifier_pubkey.is_some();

                    let authorized = if attestation_possible {
                        self.check_attestation(&effective_sender, &domains, &allowlist)
                            .await
                    } else {
                        None
                    };

                    match authorized {
                        Some(reason) => {
                            tracing::info!(
                                "Deposit open authorized via attestation: sender {} ({})",
                                &effective_sender[..16.min(effective_sender.len())],
                                reason
                            );
                        }
                        None => {
                            tracing::warn!(
                                "Deposit open rejected: effective sender {} not on allowlist and no valid attestation",
                                &effective_sender[..16.min(effective_sender.len())]
                            );
                            let code = if attestation_possible {
                                "attestation_required"
                            } else {
                                "not_authorized"
                            };
                            let mut err_data = serde_json::json!({"code": code});
                            if attestation_possible {
                                if let Some(ref vk) = self.attestation_verifier_pubkey {
                                    err_data["verifier_pubkey"] = serde_json::json!(vk);
                                }
                                if !domains.is_empty() {
                                    let domain_list: Vec<String> = domains.iter().cloned().collect();
                                    err_data["allowed_domains"] = serde_json::json!(domain_list);
                                }
                            }
                            return (
                                false,
                                Some(err_data.to_string()),
                                Some("Not authorized to open deposits on this ledger".to_string()),
                            );
                        }
                    }
                }
            }
        }

        // Resolve to ledger_id (handles both hash and reserves_key formats)
        let ledger_id = match self.resolve_to_ledger_id(&request.ledger_id) {
            Ok(lid) => lid,
            Err(e) => return (false, None, Some(e)),
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

        let _deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
        };

        // Fetch the advertisement to get fee minimums
        let advertisement = match self
            .nostr
            .fetch_ledger_advertisement(&request.ledger_id)
            .await
        {
            Ok(Some(ad)) => ad,
            Ok(None) => {
                tracing::warn!(
                    "No advertisement found for ledger {}, using zero fee minimums",
                    &request.ledger_id[..16]
                );
                crate::nostr::LedgerAdvertisement::new(
                    request.ledger_id.clone(),
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
                crate::nostr::LedgerAdvertisement::new(
                    request.ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
        };

        let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();

        // Extract fee parameters from request OR use advertisement defaults
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

        let fees = if request.params.get("fee_fixed").is_some()
            || request.params.get("fee_bps").is_some()
        {
            FeeStructure {
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

        // Check if receiving requires wallet signature
        let receive_requires_sig = request
            .params
            .get("receive_requires_sig")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Validate proposed fees meet operator minimums
        if let Err(e) = deposits_core::operation_validation::validate_fee_minimum(
            &fees,
            min_annual_bps,
            min_fixed_per_period,
        ) {
            return (false, None, Some(format!("Fee validation failed: {}", e)));
        }

        // Extract per-transfer fee schedule (optional, defaults to 2 sats fixed + 20 bps)
        let transfer_fees = {
            let fixed = request
                .params
                .get("transfer_fee_fixed")
                .and_then(|v| v.as_u64());
            let rate = request
                .params
                .get("transfer_fee_rate_bps")
                .and_then(|v| v.as_u64());
            if fixed.is_some() || rate.is_some() {
                Some(deposits_core::TransferFeeSchedule::new(
                    fixed.unwrap_or(2),
                    rate.unwrap_or(20) as u16,
                ))
            } else {
                None // will use default (100 sats, 0 bps)
            }
        };

        // Create descriptor from pubkey (single-key deposit)
        let descriptor = format!("pk({})", deposit_pubkey_str);

        // Validate descriptor size against quorum's max_descriptor_bytes
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                let max_bytes = ledger
                    .state
                    .quorum_members
                    .iter()
                    .filter_map(|m| m.max_descriptor_bytes)
                    .min();
                if let Some(limit) = max_bytes {
                    if descriptor.len() as u32 > limit {
                        return (
                            false,
                            None,
                            Some(format!(
                                "Descriptor size {} bytes exceeds quorum limit of {} bytes",
                                descriptor.len(),
                                limit
                            )),
                        );
                    }
                }
            }
        }

        // Open the deposit with co-signing
        match self
            .open_deposit(
                &ledger_id,
                &descriptor,
                Some(fees),
                transfer_fees,
                receive_requires_sig,
            )
            .await
        {
            Ok(deposit) => {
                let result = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey_str,
                    "balance": deposit.balance,
                    "fees": {
                        "fixed": deposit.fees.annualized_msats,
                        "bps": deposit.fees.annualized_bps,
                        "frequency": deposit.fees.frequency_blocks,
                    },
                    "transfer_fees": {
                        "fixed_msats": deposit.transfer_fees.fixed_msats,
                        "rate_bps": deposit.transfer_fees.rate_bps,
                    }
                });
                tracing::info!("Deposit opened for {}...", &deposit_pubkey_str[..16]);
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Failed to open deposit: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    pub(crate) async fn process_make_offer_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing make_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Verify the ledger exists (ledger_id may be a hash or reserves_id)
        let resolved_ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            // Already a 64-char hex ledger_id hash
            request.ledger_id.clone()
        } else {
            // It's a reserves_id, look up the ledger to get its ledger_id
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", &request.ledger_id[..16])),
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
        let advertisement = match self
            .nostr
            .fetch_ledger_advertisement(&resolved_ledger_id)
            .await
        {
            Ok(Some(ad)) => ad,
            Ok(None) => {
                tracing::warn!(
                    "No advertisement found for ledger {}, using zero fee minimums",
                    &resolved_ledger_id[..16]
                );
                crate::nostr::LedgerAdvertisement::new(
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
                crate::nostr::LedgerAdvertisement::new(
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

            FeeStructure {
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

        // Check if the deposit (if it already exists) requires a receive signature
        {
            let descriptor = format!("pk({})", deposit_pubkey_str);
            let deposit_id = compute_deposit_id(&descriptor);
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&resolved_ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                    if deposit.receive_requires_sig {
                        // Verify receive signature from deposit key
                        use bitcoin::secp256k1::{schnorr::Signature, Message};
                        let recv_sig_hex = match request
                            .params
                            .get("receive_signature")
                            .and_then(|v| v.as_str())
                        {
                            Some(s) => s,
                            None => {
                                return (
                                    false,
                                    None,
                                    Some(
                                        "Deposit requires receive_signature for offers".to_string(),
                                    ),
                                )
                            }
                        };
                        let recv_sig = match hex::decode(recv_sig_hex)
                            .ok()
                            .and_then(|bytes| Signature::from_slice(&bytes).ok())
                        {
                            Some(sig) => sig,
                            None => {
                                return (false, None, Some("Invalid receive_signature".to_string()))
                            }
                        };
                        // Sign the deposit_id to authorize receiving
                        let recv_msg = Message::from_digest({
                            let mut h = [0u8; 32];
                            h[..16].copy_from_slice(&deposit_id);
                            h
                        });
                        let dest_pubkey = deposit_pubkey.x_only_public_key().0;
                        let secp = &self.secp;
                        if secp
                            .verify_schnorr(&recv_sig, &recv_msg, &dest_pubkey)
                            .is_err()
                        {
                            return (false, None, Some("Invalid receive_signature".to_string()));
                        }
                    }
                }
            }
        }

        // Sync wallet to get current block height
        if let Err(e) = self.sync_wallet() {
            return (false, None, Some(format!("Failed to sync wallet: {}", e)));
        }

        // Check collateral obligation limits before creating the offer
        if let Some(err) =
            self.check_collateral_obligation_limit(&resolved_ledger_id, max_sats * 1000)
        {
            return (false, None, Some(err));
        }

        // Check per-deposit balance limit
        let descriptor = format!("pk({})", deposit_pubkey_str);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
        if let Some(err) =
            self.check_deposit_balance_limit(&resolved_ledger_id, &deposit_id, max_sats * 1000)
        {
            return (false, None, Some(err));
        }

        // Create the offer using ledger_id (stable across custody transfers)
        match self.create_deposit_offer(
            &resolved_ledger_id,
            deposit_pubkey,
            max_sats,
            min_sats,
            blocks_valid,
            Some(fees),
        ) {
            Ok(offer) => {
                // Check if we need a co-signature (post-rotation)
                let requires_cosign = self.is_quorum_active(&resolved_ledger_id);

                if requires_cosign {
                    // Request co-signature from quorum members (retry up to 3 times)
                    let max_attempts = 3;
                    let mut cosign_ok = None;
                    let mut last_err = String::new();
                    for attempt in 1..=max_attempts {
                        match self.request_offer_cosign(&resolved_ledger_id, &offer).await {
                            Ok(result) => {
                                cosign_ok = Some(result);
                                break;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Offer cosign attempt {}/{} failed: {}",
                                    attempt,
                                    max_attempts,
                                    e
                                );
                                last_err = e.to_string();
                                if attempt < max_attempts {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(500))
                                        .await;
                                }
                            }
                        }
                    }
                    match cosign_ok {
                        Some(cosign_result) => {
                            let result = serde_json::json!({
                                "offer_id": hex::encode(offer.offer_id),
                                "operator_id": pubkey_hex(&offer.operator_id),
                                "funding_address": offer.funding_address,
                                "deadline_block": offer.deadline_block,
                                "created_at_block": offer.created_at_block,
                                "max_sats": max_sats,
                                "min_sats": min_sats,
                                "cosign_required": true,
                                "cosigner_pubkey": pubkey_hex(&cosign_result.cosigner_pubkey),
                                "cosigner_ledger_hash": hex::encode(cosign_result.member_ledger_hash),
                                "cosign_signature": hex::encode(cosign_result.signature),
                            });
                            tracing::info!(
                                "Deposit offer created with co-signature: {}...",
                                &hex::encode(&offer.offer_id[..8])
                            );
                            (true, Some(result.to_string()), None)
                        }
                        None => {
                            tracing::warn!(
                                "Failed to get co-signature for offer after {} attempts: {}",
                                max_attempts,
                                last_err
                            );
                            (
                                false,
                                None,
                                Some(format!("Co-signature required but failed: {}", last_err)),
                            )
                        }
                    }
                } else {
                    // Pre-rotation: no co-signature required
                    let result = serde_json::json!({
                        "offer_id": hex::encode(offer.offer_id),
                        "operator_id": pubkey_hex(&offer.operator_id),
                        "funding_address": offer.funding_address,
                        "deadline_block": offer.deadline_block,
                        "created_at_block": offer.created_at_block,
                        "max_sats": max_sats,
                        "min_sats": min_sats,
                        "cosign_required": false,
                    });
                    tracing::info!(
                        "Deposit offer created: {}...",
                        &hex::encode(&offer.offer_id[..8])
                    );
                    (true, Some(result.to_string()), None)
                }
            }
            Err(e) => {
                tracing::warn!("Failed to create deposit offer: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Process an offer status query request
    ///
    /// Params:
    /// - offer_id: hex-encoded 32-byte offer ID (optional)
    /// - deposit_pubkey: hex-encoded depositor pubkey (optional, used if offer_id not found)
    ///
    /// If offer_id is found, returns the offer status.
    /// If offer_id is not found but deposit_pubkey is provided, checks if the deposit
    /// exists in the ledger (meaning the offer was completed).
    pub(crate) async fn process_offer_status_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::types::DepositOfferStatus;

        // Extract offer_id from params
        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };

        // Also extract deposit_pubkey if provided (for fallback lookup)
        let deposit_pubkey_hex = request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str());

        // Parse hex offer_id
        let offer_id_bytes = match hex::decode(offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => return (false, None, Some("offer_id must be 32 bytes".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid offer_id hex: {}", e))),
        };

        // Look up the offer
        match self.get_deposit_offer(&offer_id_bytes) {
            Some((offer, status)) => {
                let status_json = match status {
                    DepositOfferStatus::Pending => serde_json::json!({
                        "status": "pending",
                    }),
                    DepositOfferStatus::FundingReceived {
                        txid,
                        amount_sats,
                        detected_at_block,
                    } => serde_json::json!({
                        "status": "funding_received",
                        "txid": txid,
                        "amount_sats": amount_sats,
                        "detected_at_block": detected_at_block,
                    }),
                    DepositOfferStatus::Completed {
                        txid,
                        amount_sats,
                        confirmed_at_block,
                    } => serde_json::json!({
                        "status": "completed",
                        "txid": txid,
                        "amount_sats": amount_sats,
                        "confirmed_at_block": confirmed_at_block,
                    }),
                    DepositOfferStatus::Expired { expired_at_block } => serde_json::json!({
                        "status": "expired",
                        "expired_at_block": expired_at_block,
                    }),
                    DepositOfferStatus::Cancelled => serde_json::json!({
                        "status": "cancelled",
                    }),
                };

                let result = serde_json::json!({
                    "offer_id": offer_id_hex,
                    "funding_address": offer.funding_address,
                    "ledger_id": offer.ledger_id,
                    "max_sats": offer.max_amount_sats,
                    "min_sats": offer.min_amount_sats,
                    "deadline_block": offer.deadline_block,
                    "status": status_json,
                });

                tracing::debug!(
                    "Offer status query: {}... -> {:?}",
                    &offer_id_hex[..16],
                    status_json
                );
                (true, Some(result.to_string()), None)
            }
            None => {
                // Offer not in our tracking. If we have deposit_pubkey, check if the deposit
                // exists in the ledger (meaning it was funded and completed).
                if let Some(pubkey_hex) = deposit_pubkey_hex {
                    // Convert pubkey to deposit_id
                    let descriptor = format!("pk({})", pubkey_hex);
                    let deposit_id = compute_deposit_id(&descriptor);

                    // Check if deposit exists in the ledger
                    if let Some((_, ledger)) = self
                        .get_ledger_by_ledger_id(&request.ledger_id)
                        .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
                    {
                        if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                            // Deposit exists - offer must have completed
                            let result = serde_json::json!({
                                "offer_id": offer_id_hex,
                                "status": {
                                    "status": "completed",
                                    "amount_sats": deposit.balance / 1000,
                                },
                            });
                            tracing::debug!(
                                "Offer status query: {}... -> completed (from ledger)",
                                &offer_id_hex[..16]
                            );
                            return (true, Some(result.to_string()), None);
                        }
                    }
                }

                // No offer and no deposit found
                let result = serde_json::json!({
                    "offer_id": offer_id_hex,
                    "status": {
                        "status": "not_found",
                    },
                });
                tracing::debug!(
                    "Offer status query: {}... -> not found",
                    &offer_id_hex[..16]
                );
                (true, Some(result.to_string()), None)
            }
        }
    }

    /// Process a balance query request
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey (legacy, converted to deposit_id)
    ///
    /// Returns the current balance in the ledger (in millisatoshis)
    pub(crate) async fn process_balance_query_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        // Extract deposit_pubkey from params
        let deposit_pubkey_hex = match request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(pk) => pk,
            None => {
                return (
                    false,
                    None,
                    Some("Missing deposit_pubkey parameter".to_string()),
                )
            }
        };

        // Convert pubkey hex to deposit_id via descriptor
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Find the ledger
        let (_, ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Look up the deposit balance
        match ledger.state.deposits.get(&deposit_id) {
            Some(deposit) => {
                let block_height = self.wallet.get_block_height().unwrap_or(0);
                let result = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "balance_msats": deposit.balance,
                    "balance_sats": deposit.balance / 1000,
                    "locked_msats": deposit.locked_balance,
                    "block_height": block_height,
                });
                tracing::debug!(
                    "Balance query: {}... -> {} msats",
                    &deposit_pubkey_hex[..16],
                    deposit.balance
                );
                (true, Some(result.to_string()), None)
            }
            None => (
                false,
                None,
                Some(format!(
                    "Deposit not found for pubkey: {}...",
                    &deposit_pubkey_hex[..16]
                )),
            ),
        }
    }

    pub(crate) async fn process_complete_offer_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing complete_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };
        let txid = match request.params.get("txid").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return (false, None, Some("Missing txid parameter".to_string())),
        };
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

        let offer_id_bytes = match hex::decode(offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid offer_id (must be 64 hex chars)".to_string()),
                )
            }
        };
        let mut offer_id = [0u8; 32];
        offer_id.copy_from_slice(&offer_id_bytes);

        // Sync wallet to see on-chain funding
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed before complete_offer: {}", e);
        }

        match self
            .complete_deposit_offer(&offer_id, txid, amount_sats)
            .await
        {
            Ok(new_balance) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "new_balance_msats": new_balance,
                    "new_balance_sats": new_balance / 1000,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("complete_offer failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    pub(crate) async fn process_deposit_credit_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing deposit_credit request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let deposit_pubkey_hex = match request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing deposit_pubkey parameter".to_string()),
                )
            }
        };
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
        let invoice_id = match request.params.get("invoice_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing invoice_id parameter".to_string()),
                )
            }
        };

        // Compute deposit_id from pubkey
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

        // Generate payment hash from invoice_id
        use bitcoin::hashes::{sha256, Hash};
        let payment_hash = sha256::Hash::hash(invoice_id.as_bytes()).to_byte_array();

        match self
            .credit_deposit(
                &request.ledger_id,
                deposit_id,
                amount_msats,
                payment_hash,
                invoice_id,
            )
            .await
        {
            Ok(new_balance) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "new_balance_msats": new_balance,
                    "new_balance_sats": new_balance / 1000,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("deposit_credit failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Admin: create a reserves UTXO from the wallet's on-chain balance.
    /// Params: `{amount_sats: u64}` (defaults to available balance - 1000 if missing).
    pub(crate) async fn process_reserves_create_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        if let Err(e) = self.sync_wallet() {
            return (false, None, Some(format!("wallet sync failed: {}", e)));
        }
        let balance = match self.wallet_balance() {
            Ok(b) => b,
            Err(e) => return (false, None, Some(format!("wallet_balance: {}", e))),
        };

        // If the caller specified an amount, honor it; otherwise consume the
        // full balance minus a small reserve for the transaction fee.
        let amount_sats = request
            .params
            .get("amount_sats")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| balance.saturating_sub(1000));
        if amount_sats + 1000 > balance {
            return (
                false,
                None,
                Some(format!(
                    "insufficient balance: {} sats (need {} + fees)",
                    balance, amount_sats
                )),
            );
        }

        let reserves = match self.create_reserves(amount_sats, vec![], 0) {
            Ok(r) => r,
            Err(e) => return (false, None, Some(format!("create_reserves: {}", e))),
        };
        let txid = match self.wallet.broadcast(&reserves.tx) {
            Ok(t) => t,
            Err(e) => return (false, None, Some(format!("broadcast: {}", e))),
        };

        let result = serde_json::json!({
            "txid": txid.to_string(),
            "vout": reserves.outpoint.vout,
            "amount_sats": reserves.amount,
            "address": reserves.address.to_string(),
            "timeout_height": reserves.timeout_height,
        });
        (true, Some(result.to_string()), None)
    }

    /// Admin: open a ledger against an existing reserves UTXO.
    pub(crate) async fn process_ledger_open_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        if let Err(e) = self.sync_wallet() {
            return (false, None, Some(format!("wallet sync failed: {}", e)));
        }

        let ledger = match self.open_ledger() {
            Ok(l) => l,
            Err(e) => return (false, None, Some(format!("open_ledger: {}", e))),
        };
        let ledger_id = ledger.ledger_id_hex();

        // Mark dirty so the run loop's broadcast-dirty pass picks it up. We
        // can't call broadcast_all_updates here directly: it holds a ledger
        // read-guard across an await, and this handler is invoked from a
        // Send-requiring tokio::spawn in main_loop.
        self.dirty_ledgers
            .lock()
            .unwrap()
            .insert(ledger_id.clone());

        let result = serde_json::json!({
            "ledger_id": ledger_id,
            "reserves_key": ledger.state.reserves_key,
            "operator": ledger.state.operator_key.to_string(),
        });
        (true, Some(result.to_string()), None)
    }
}
