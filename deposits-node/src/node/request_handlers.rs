use super::*;

impl Node {
    // ========================================================================
    // Request Handlers
    // These process incoming Nostr requests for ledger operations.
    // ========================================================================

    /// Resolve the "effective sender" of a request, collapsing DEP-04
    /// subkey delegation so downstream ACL checks see the account
    /// pubkey rather than the delegated signer.
    ///
    /// When a request carries `["v", <account>]` + `["va", <sig>]` tags,
    /// this verifies:
    ///   - `sig` is a valid BIP-340 Schnorr signature, by `account`, over
    ///     `SHA256("nostr301:" + sender)`;
    ///   - the account has published a Kind 10301 list that includes the
    ///     sender in `inbox_keys` AND does NOT list it in
    ///     `revoked_subkeys`.
    ///
    /// On success returns the account pubkey (hex xonly). With no
    /// delegation tags, returns the original sender unchanged. An invalid
    /// or revoked delegation returns `Err(...)` so callers can reject
    /// the request with a clear code instead of silently falling back
    /// to the direct sender.
    pub(crate) async fn resolve_attested_sender(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<String, String> {
        let (account, sig_hex) =
            match (&request.subkey_account, &request.subkey_attestation) {
                (Some(a), Some(s)) => (a, s),
                (None, None) => return Ok(request.sender.clone()),
                _ => {
                    return Err(
                        "subkey delegation requires BOTH `v` and `va` tags".to_string()
                    );
                }
            };

        // Sanity-check hex lengths up front so we can produce a clean
        // error before paying for Schnorr verification / Nostr fetches.
        if account.len() != 64 || !account.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("subkey account `{}` is not 32-byte xonly hex", account));
        }
        if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("subkey attestation must be 64-byte hex (Schnorr)".to_string());
        }

        // ── Verify the Schnorr attestation: sig(msg, account) ──
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{schnorr, Message, XOnlyPublicKey};
        let msg_str = format!("nostr301:{}", request.sender);
        let digest = sha256::Hash::hash(msg_str.as_bytes());
        let msg = Message::from_digest(digest.to_byte_array());

        let account_bytes = hex::decode(account)
            .map_err(|e| format!("invalid subkey account hex: {}", e))?;
        let xonly = XOnlyPublicKey::from_slice(&account_bytes)
            .map_err(|e| format!("invalid subkey account xonly: {}", e))?;
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| format!("invalid subkey attestation hex: {}", e))?;
        let sig = schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid Schnorr signature: {}", e))?;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|_| "subkey attestation signature failed verification".to_string())?;

        // ── Policy check: Kind 10301 list must include sender as
        //    active (in inbox_keys) and NOT revoked. ──
        let (inbox, revoked) = self
            .nostr
            .fetch_subkey_list(account)
            .await
            .map_err(|e| format!("failed to fetch subkey list for {}: {}", &account[..16], e))?;
        if revoked.iter().any(|k| k == &request.sender) {
            return Err(format!(
                "sender {} is revoked on account {}'s subkey list",
                &request.sender[..16],
                &account[..16]
            ));
        }
        if !inbox.iter().any(|k| k == &request.sender) {
            return Err(format!(
                "sender {} is not in account {}'s inbox_keys",
                &request.sender[..16],
                &account[..16]
            ));
        }

        tracing::info!(
            "Resolved subkey {} → account {} via DEP-04 attestation",
            &request.sender[..16.min(request.sender.len())],
            &account[..16]
        );
        Ok(account.clone())
    }

    /// Check whether an incoming request is authorized to invoke admin-class
    /// actions (e.g. `ledger_open`, `reserves_create`). Admin requests must
    /// be gift-wrapped and the unwrapped sender must match either our own
    /// operator pubkey (local CLI using the operator seed) or the admin
    /// pubkey registered at bootstrap (remote admin with their own key).
    ///
    /// Returns `Ok(())` if authorized; otherwise returns the standard
    /// handler failure tuple for the caller to return directly.
    pub(crate) fn check_admin_authorized(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<(), (bool, Option<String>, Option<String>)> {
        let Some(sender_hex) = request.gift_wrap_sender.as_deref() else {
            return Err((
                false,
                None,
                Some("admin request must be gift-wrapped".to_string()),
            ));
        };

        // Our operator identity as x-only hex (nostr key == operator key).
        let our_xonly = {
            let (xo, _) = self.node_id.x_only_public_key();
            hex::encode(xo.serialize())
        };
        if sender_hex == our_xonly {
            return Ok(());
        }

        if let Some(admin_pk) = &self.admin_pubkey {
            if sender_hex == admin_pk.to_hex() {
                return Ok(());
            }
        }

        Err((
            false,
            None,
            Some(format!(
                "admin request from {}: not operator or registered admin",
                &sender_hex[..16.min(sender_hex.len())]
            )),
        ))
    }

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
                let on_allowlist = self
                    .deposit_allowlist
                    .read()
                    .unwrap()
                    .contains(&effective_sender);

                if on_allowlist {
                    // Explicitly allowed
                } else {
                    // Check for a lightning-verify attestation with an allowed domain
                    let domains: std::collections::HashSet<String> =
                        self.deposit_domain_allowlist.read().unwrap().clone();

                    let has_domains = !domains.is_empty();
                    let authorized = if has_domains {
                        self.check_attestation_domain(&effective_sender, &domains)
                            .await
                    } else {
                        None
                    };

                    match authorized {
                        Some(domain) => {
                            tracing::info!(
                                "Deposit open authorized via attestation: sender {} domain {}",
                                &effective_sender[..16.min(effective_sender.len())],
                                domain
                            );
                        }
                        None => {
                            tracing::warn!(
                                "Deposit open rejected: effective sender {} not on allowlist and no valid attestation",
                                &effective_sender[..16.min(effective_sender.len())]
                            );
                            let code = if has_domains {
                                "attestation_required"
                            } else {
                                "not_authorized"
                            };
                            let mut err_data = serde_json::json!({"code": code});
                            if has_domains {
                                if let Some(ref vk) = self.attestation_verifier_pubkey {
                                    err_data["verifier_pubkey"] = serde_json::json!(vk);
                                }
                                let domain_list: Vec<String> = domains.iter().cloned().collect();
                                err_data["allowed_domains"] = serde_json::json!(domain_list);
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

    /// Process a make_invoice request - create Lightning invoice for deposit credit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning invoice`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - amount_sats: amount for the invoice
    /// - description: optional invoice description
    pub(crate) async fn process_make_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
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

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Check if deposit requires receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                    if deposit.receive_requires_sig {
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
                                        "Deposit requires receive_signature for invoices"
                                            .to_string(),
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
                        let dest_pubkey = match hex::decode(deposit_pubkey_hex)
                            .ok()
                            .and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok())
                        {
                            Some(pk) => pk.x_only_public_key().0,
                            None => {
                                return (false, None, Some("Invalid deposit_pubkey".to_string()))
                            }
                        };
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

        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => {
                return (
                    false,
                    None,
                    Some("Missing amount_sats parameter".to_string()),
                )
            }
        };

        let description = request
            .params
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("Deposit credit");

        let amount_msat = amount_sats * 1000;

        // Check collateral obligation limits before creating the invoice
        if let Some(err) = self.check_collateral_obligation_limit(&request.ledger_id, amount_msat) {
            return (false, None, Some(err));
        }

        // Check per-deposit balance limit
        if let Some(err) =
            self.check_deposit_balance_limit(&request.ledger_id, &deposit_id, amount_msat)
        {
            return (false, None, Some(err));
        }

        // Create invoice via LdkCli (same as `deposits-node lightning invoice`)
        let cli = LdkCli::from_env();

        match cli.create_invoice(amount_msat, description) {
            Ok(invoice_str) => {
                // Parse the invoice to get the payment hash
                let payment_hash = match Bolt11Invoice::from_str(&invoice_str) {
                    Ok(inv) => {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(inv.payment_hash().as_ref());
                        hash
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse created invoice: {}", e);
                        // Generate a hash from the invoice string as fallback
                        use bitcoin::hashes::{sha256, Hash};
                        let hash = sha256::Hash::hash(invoice_str.as_bytes());
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash.as_ref());
                        arr
                    }
                };

                // Track the pending invoice for crediting when paid
                let pending = PendingInvoice {
                    ledger_id: request.ledger_id.clone(),
                    deposit_id,
                    descriptor: descriptor.clone(),
                    amount_msat,
                    invoice: invoice_str.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    payment_hash_hex: hex::encode(payment_hash),
                };

                self.pending_invoices
                    .lock()
                    .unwrap()
                    .insert(payment_hash, pending);
                self.save_pending_invoices();

                tracing::info!(
                    "Created invoice for {}... amount={} sats, hash={}",
                    &deposit_pubkey_hex[..16.min(deposit_pubkey_hex.len())],
                    amount_sats,
                    hex::encode(&payment_hash[..8])
                );

                // Request co-signature from quorum member (if post-rotation)
                let requires_cosign = self.is_quorum_active(&request.ledger_id);
                if requires_cosign {
                    let params = serde_json::json!({
                        "payment_hash": hex::encode(payment_hash),
                        "deposit_id": hex::encode(deposit_id),
                        "amount_msat": amount_msat,
                        "invoice": &invoice_str,
                    });

                    let mut notification_rx = self.nostr.create_notification_receiver();
                    let req_id = match self
                        .nostr
                        .send_ledger_request(&request.ledger_id, "cosign_invoice", params)
                        .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            return (
                                false,
                                None,
                                Some(format!("Failed to send cosign_invoice: {:?}", e)),
                            );
                        }
                    };
                    self.track_sent_event(&req_id);

                    // Poll for response (3s timeout)
                    let deadline =
                        tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
                    let mut cosign_result: Option<serde_json::Value> = None;
                    loop {
                        // Drain notifications to trigger response processing
                        match tokio::time::timeout(
                            tokio::time::Duration::from_millis(100),
                            notification_rx.recv(),
                        )
                        .await
                        {
                            Ok(Ok(n)) => {
                                self.nostr.dispatch_or_extract_request(n, "");
                            }
                            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                            _ => {}
                        }
                        // Check for our response
                        while let Some(response) = self.nostr.try_recv_response() {
                            if response.request_id == req_id && response.success {
                                cosign_result = response.result.clone();
                                break;
                            }
                        }
                        if cosign_result.is_some() || tokio::time::Instant::now() >= deadline {
                            break;
                        }
                    }

                    match cosign_result {
                        Some(r) => {
                            let result = serde_json::json!({
                                "invoice": invoice_str,
                                "amount_sats": amount_sats,
                                "deposit_pubkey": deposit_pubkey_hex,
                                "deposit_id": hex::encode(deposit_id),
                                "payment_hash": hex::encode(payment_hash),
                                "cosign_required": true,
                                "cosigner_pubkey": r.get("cosigner_pubkey").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosigner_ledger_hash": r.get("cosigner_ledger_hash").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosign_signature": r.get("cosign_signature").and_then(|v| v.as_str()).unwrap_or(""),
                            });
                            (true, Some(result.to_string()), None)
                        }
                        None => (
                            false,
                            None,
                            Some(
                                "Invoice co-signature required but no quorum member responded"
                                    .to_string(),
                            ),
                        ),
                    }
                } else {
                    let result = serde_json::json!({
                        "invoice": invoice_str,
                        "amount_sats": amount_sats,
                        "deposit_pubkey": deposit_pubkey_hex,
                        "deposit_id": hex::encode(deposit_id),
                        "payment_hash": hex::encode(payment_hash),
                    });
                    (true, Some(result.to_string()), None)
                }
            }
            Err(e) => {
                tracing::error!("Failed to create invoice: {}", e);
                (
                    false,
                    None,
                    Some(format!("Failed to create invoice: {}", e)),
                )
            }
        }
    }

    /// Process a pay_invoice request - pay Lightning invoice from deposit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning pay`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - invoice: bolt11 invoice string
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over payment message
    pub(crate) async fn process_pay_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};
        use deposits_core::messages::LedgerOperation;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
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

        let invoice_str = match request.params.get("invoice").and_then(|v| v.as_str()) {
            Some(i) => i,
            None => return (false, None, Some("Missing invoice parameter".to_string())),
        };

        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                return (
                    false,
                    None,
                    Some("Missing payment_hash parameter".to_string()),
                )
            }
        };

        let amount_msat = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => {
                return (
                    false,
                    None,
                    Some("Missing amount_msats parameter".to_string()),
                )
            }
        };

        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature parameter".to_string())),
        };

        // Parse payment_hash from client
        let mut payment_id = [0u8; 32];
        match hex::decode(payment_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => payment_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        }

        // Parse the BOLT11 invoice and verify it matches client's payment_hash and amount
        let invoice = match Bolt11Invoice::from_str(invoice_str) {
            Ok(inv) => inv,
            Err(e) => return (false, None, Some(format!("Invalid invoice: {}", e))),
        };

        let invoice_payment_hash = invoice.payment_hash();
        let invoice_hash_bytes: &[u8] = invoice_payment_hash.as_ref();
        if invoice_hash_bytes != payment_id {
            return (
                false,
                None,
                Some("payment_hash does not match invoice".to_string()),
            );
        }

        let invoice_amount = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_amount != amount_msat {
            return (
                false,
                None,
                Some("amount_msats does not match invoice".to_string()),
            );
        }

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Parse pubkey for signature verification
        let deposit_pubkey = match hex::decode(deposit_pubkey_hex)
            .ok()
            .and_then(|bytes| bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok())
        {
            Some(pk) => pk,
            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
        };

        // Verify INVOICE signature (deposit_id, payment_hash, amount)
        let secp = Secp256k1::verification_only();
        let msg_hash = deposits_core::signature_utils::invoice_lock_signing_message(
            &deposit_id,
            &payment_id,
            amount_msat,
        );
        let msg = Message::from_digest(msg_hash);

        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (false, None, Some("Invalid signature format".to_string())),
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return (false, None, Some("Invalid signature".to_string())),
        };

        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from(deposit_pubkey);
        if secp.verify_schnorr(&signature, &msg, &xonly).is_err() {
            return (
                false,
                None,
                Some("Signature verification failed".to_string()),
            );
        }

        // Find the ledger and check deposit balance
        let ledger_id = &request.ledger_id;
        let ledger_arc = match self.handler.ledgers.lock().unwrap().get(ledger_id).cloned() {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let sequence_number = {
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Deposit not found".to_string())),
            };

            if deposit.balance < amount_msat {
                return (
                    false,
                    None,
                    Some(format!(
                        "Insufficient balance: {} msat available, {} msat needed",
                        deposit.balance, amount_msat
                    )),
                );
            }

            ledger.next_sequence()
        };

        // Create witness from signature
        let witness = DescriptorWitness {
            stack: vec![sig_bytes.clone()],
        };

        let lock_operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msat,
            payment_id,
            sequence_number,
            witness: witness.clone(),
        };

        // Commit the lock operation via staged flow
        if let Err(e) = self.commit_operation(ledger_id, lock_operation).await {
            return (false, None, Some(format!("Failed to lock funds: {}", e)));
        }

        tracing::info!(
            "Locked {} msat for payment {}",
            amount_msat,
            hex::encode(&payment_id[..8])
        );

        // Check for self-pay: if this invoice was created by us (exists in pending_invoices),
        // settle internally without touching LDK. This handles the case where a depositor
        // pays an invoice created for another depositor on the same operator.
        let self_pay = self
            .pending_invoices
            .lock()
            .unwrap()
            .contains_key(&payment_id);

        if self_pay {
            tracing::info!(
                "Self-pay detected for payment {}... — settling internally",
                hex::encode(&payment_id[..8])
            );

            // Look up the pending invoice to find the destination deposit
            let pending = self.pending_invoices.lock().unwrap().remove(&payment_id);
            self.save_pending_invoices();
            if let Some(pending) = pending {
                // Fulfill the lock (debit sender)
                let fulfill_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let fulfill_operation = LedgerOperation::InvoiceFulfill {
                    deposit_id,
                    amount: amount_msat,
                    payment_id,
                    sequence_number: fulfill_sequence,
                    witness: witness.clone(),
                    preimage: [0u8; 32],
                };

                if let Err(e) = self.commit_operation(ledger_id, fulfill_operation).await {
                    return (
                        false,
                        None,
                        Some(format!("Failed to fulfill self-pay: {}", e)),
                    );
                }

                // Credit the destination deposit
                let credit_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let credit_operation = LedgerOperation::InvoiceCredit {
                    payment_hash: payment_id,
                    deposit_id: pending.deposit_id,
                    amount: amount_msat,
                    invoice_id: pending.invoice.clone(),
                    sequence_number: credit_sequence,
                };

                if let Err(e) = self.commit_operation(ledger_id, credit_operation).await {
                    tracing::error!("Failed to credit destination deposit: {}", e);
                }

                tracing::info!(
                    "Self-pay settled: {} msat from {} to {}",
                    amount_msat,
                    hex::encode(&deposit_id[..4]),
                    hex::encode(&pending.deposit_id[..4])
                );

                let result = serde_json::json!({
                    "payment_id": hex::encode(payment_id),
                    "deposit_pubkey": deposit_pubkey_hex,
                    "amount_msat": amount_msat,
                    "status": "succeeded",
                    "self_pay": true,
                });
                return (true, Some(result.to_string()), None);
            }
        }

        // Pay invoice via LdkCli — dispatch payment and return immediately.
        // The background auto_complete_outbound_payments task will poll LDK
        // and commit InvoiceFulfill or InvoiceFail.
        let cli = LdkCli::from_env();
        match cli.pay_invoice(invoice_str) {
            Ok(_) => {
                tracing::info!(
                    "LDK payment dispatched for {}..., will complete in background",
                    hex::encode(&payment_id[..8])
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                // "already initiated" means the invoice exists on the shared LDK node
                // (created by another operator). This is cross-node self-pay — the payment
                // will settle internally via LDK. Let auto_complete_outbound_payments handle it.
                if err_str.contains("already been initiated")
                    || err_str.contains("already initiated")
                {
                    tracing::info!("Cross-node self-pay detected for {}... (shared LDK node), will complete in background",
                        hex::encode(&payment_id[..8]));
                } else {
                    tracing::warn!(
                        "LDK pay_invoice failed for {}...: {}, failing lock",
                        hex::encode(&payment_id[..8]),
                        e
                    );

                    let fail_sequence = {
                        let ledger = ledger_arc.read().unwrap();
                        ledger.next_sequence()
                    };
                    let fail_operation = LedgerOperation::InvoiceFail {
                        deposit_id,
                        amount: amount_msat,
                        payment_id,
                        sequence_number: fail_sequence,
                    };
                    if let Err(e2) = self.commit_operation(ledger_id, fail_operation).await {
                        tracing::error!("Failed to commit fail: {}", e2);
                    }
                    return (false, None, Some(format!("Payment failed: {}", e)));
                }
            }
        }

        let result = serde_json::json!({
            "payment_id": hex::encode(payment_id),
            "deposit_pubkey": deposit_pubkey_hex,
            "amount_msat": amount_msat,
            "status": "pending",
        });
        (true, Some(result.to_string()), None)
    }

    /// Process a withdrawal request from a depositor
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - deposit_id: hex-encoded 16-byte deposit identifier
    /// - address: destination Bitcoin address
    /// - amount_sats: amount to withdraw
    /// - fee_sats: fee for the withdrawal transaction
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over WITHDRAWAL message
    pub(crate) async fn process_withdraw_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{schnorr::Signature, Message};

        tracing::info!(
            "Processing withdraw request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let deposit_pubkey_hex = match request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(p) => p,
            None => return (false, None, Some("Missing deposit_pubkey".to_string())),
        };
        let deposit_id_hex = match request.params.get("deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => return (false, None, Some("Missing deposit_id".to_string())),
        };
        let address = match request.params.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => return (false, None, Some("Missing address".to_string())),
        };
        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_sats".to_string())),
        };
        let fee_sats = match request.params.get("fee_sats").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee_sats".to_string())),
        };
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };
        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature".to_string())),
        };

        // Parse deposit pubkey
        let deposit_pubkey = match hex::decode(deposit_pubkey_hex)
            .ok()
            .and_then(|bytes| bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok())
        {
            Some(pk) => pk,
            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
        };

        // Parse deposit_id
        let mut deposit_id = [0u8; 16];
        match hex::decode(deposit_id_hex) {
            Ok(bytes) if bytes.len() == 16 => deposit_id.copy_from_slice(&bytes),
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid deposit_id (must be 16 bytes hex)".to_string()),
                )
            }
        }

        // Verify deposit_id matches pubkey
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let expected_deposit_id = compute_deposit_id(&descriptor);
        if deposit_id != expected_deposit_id {
            return (
                false,
                None,
                Some("deposit_id does not match deposit_pubkey".to_string()),
            );
        }

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid nonce (must be 32 bytes hex)".to_string()),
                )
            }
        };

        // Parse signature
        let signature = match hex::decode(signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
        {
            Some(sig) => sig,
            None => return (false, None, Some("Invalid signature".to_string())),
        };

        // Verify WITHDRAWAL signature (nonce, deposit_id, address, amount, fee)
        let msg_hash = deposits_core::signature_utils::withdrawal_signing_message(
            &nonce,
            &deposit_id,
            address,
            amount_sats,
            fee_sats,
        );
        let secp = &self.secp;
        let msg = Message::from_digest(msg_hash);
        let x_only = deposit_pubkey.x_only_public_key().0;

        if secp.verify_schnorr(&signature, &msg, &x_only).is_err() {
            return (
                false,
                None,
                Some("Invalid withdrawal signature".to_string()),
            );
        }

        // Find the ledger
        let (reserves_id, _ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Compute deposit_id from pubkey
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Create witness from signature
        let depositor_witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };

        // Lock the withdrawal with co-signing
        match self
            .lock_withdrawal(
                &reserves_id,
                deposit_id,
                address.to_string(),
                amount_sats,
                fee_sats,
                nonce,
                depositor_witness,
                None, // no memo
            )
            .await
        {
            Ok(lock_result) => {
                let withdrawal_id = lock_result.withdrawal.withdrawal_id;
                let result = serde_json::json!({
                    "status": "locked",
                    "withdrawal_id": hex::encode(withdrawal_id),
                    "message": "Withdrawal locked. Will be broadcast after lock period.",
                });
                tracing::info!("Withdrawal locked: {}", hex::encode(&withdrawal_id[..8]));
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Withdrawal failed: {}", e);
                (false, None, Some(format!("Withdrawal failed: {}", e)))
            }
        }
    }

    /// Process a transfer_lock request - lock funds for conditional transfer
    pub(crate) async fn process_transfer_lock_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::schnorr::Signature;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::types::DescriptorWitness;

        tracing::debug!(
            "Processing transfer_lock request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };
        let source_id_hex = match request
            .params
            .get("source_deposit_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return (false, None, Some("Missing source_deposit_id".to_string())),
        };
        let dest_id_hex = match request
            .params
            .get("destination_deposit_id")
            .and_then(|v| v.as_str())
        {
            Some(d) => d,
            None => {
                return (
                    false,
                    None,
                    Some("Missing destination_deposit_id".to_string()),
                )
            }
        };
        let amount_msats = match request.params.get("amount").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount".to_string())),
        };
        let fee_msats = match request.params.get("fee").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee".to_string())),
        };
        let completion_script = match request
            .params
            .get("completion_script")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return (false, None, Some("Missing completion_script".to_string())),
        };
        let timeout_height = match request
            .params
            .get("timeout_height")
            .and_then(|v| v.as_u64())
        {
            Some(t) => t as u32,
            None => return (false, None, Some("Missing timeout_height".to_string())),
        };
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature".to_string())),
        };

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid nonce".to_string())),
        };

        // Parse deposit IDs
        let mut source_deposit_id = [0u8; 16];
        match hex::decode(source_id_hex) {
            Ok(bytes) if bytes.len() == 16 => source_deposit_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid source_deposit_id".to_string())),
        }

        let mut destination_deposit_id = [0u8; 16];
        match hex::decode(dest_id_hex) {
            Ok(bytes) if bytes.len() == 16 => destination_deposit_id.copy_from_slice(&bytes),
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid destination_deposit_id".to_string()),
                )
            }
        }

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse signature
        let signature = match hex::decode(signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
        {
            Some(sig) => sig,
            None => return (false, None, Some("Invalid signature".to_string())),
        };

        // amount_msats and fee_msats already parsed from request

        // Get ledger and verify source deposit exists
        let ledger_id = &request.ledger_id;
        let deposit_descriptor = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", ledger_id)),
                    )
                }
            };
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&source_deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Source deposit not found".to_string())),
            };

            // Validate timeout_height against max_transfer_timeout_blocks (strictest quorum member)
            let max_timeout = ledger
                .state
                .quorum_members
                .iter()
                .filter_map(|m| m.max_transfer_timeout_blocks)
                .min()
                .unwrap_or(1008); // default ~1 week
            let current_block = ledger.history.last().map(|u| u.block_height).unwrap_or(0);
            if current_block > 0 && timeout_height > current_block.saturating_add(max_timeout) {
                return (
                    false,
                    None,
                    Some(format!(
                        "timeout_height {} exceeds max: current_block {} + max_timeout {} = {}",
                        timeout_height,
                        current_block,
                        max_timeout,
                        current_block.saturating_add(max_timeout)
                    )),
                );
            }

            // Validate fee against deposit's transfer fee schedule (all in msats)
            let expected_fee = deposit.transfer_fees.calculate_fee(amount_msats);
            if fee_msats != expected_fee {
                return (
                    false,
                    None,
                    Some(format!(
                    "Fee mismatch: expected {} msats (fixed={} + {}bps on {} msats), got {} msats",
                    expected_fee, deposit.transfer_fees.fixed_msats,
                    deposit.transfer_fees.rate_bps, amount_msats, fee_msats
                )),
                );
            }

            // Check sufficient balance
            let total = amount_msats + fee_msats;
            if deposit.balance < total {
                let balance_json = format!("{{\"balance_msats\":{}}}", deposit.balance);
                return (
                    false,
                    Some(balance_json),
                    Some(format!(
                        "Insufficient balance: {} msats available, {} msats needed",
                        deposit.balance, total
                    )),
                );
            }

            deposit.descriptor.clone()
        };

        // Check destination deposit balance limit
        if let Some(err) = self.check_deposit_balance_limit(
            &request.ledger_id,
            &destination_deposit_id,
            amount_msats,
        ) {
            return (false, None, Some(err));
        }

        // Verify signature
        let _secp = &self.secp;
        let msg_hash = deposits_core::signature_utils::transfer_lock_signing_message(
            &nonce,
            &source_deposit_id,
            &destination_deposit_id,
            amount_msats,
            fee_msats,
            completion_script,
            timeout_height,
        );

        // Verify signature against deposit descriptor (supports any miniscript)
        let witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };
        match deposits_core::descriptor::verify_witness(&deposit_descriptor, &witness, &msg_hash) {
            Ok(true) => {}
            Ok(false) => return (false, None, Some("Invalid signature".to_string())),
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Descriptor verification failed: {}", e)),
                )
            }
        }

        // Check if destination deposit requires a receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(dest_deposit) = ledger.state.deposits.get(&destination_deposit_id) {
                    if dest_deposit.receive_requires_sig {
                        // Verify receive signature from destination deposit key
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
                                        "Destination deposit requires receive_signature"
                                            .to_string(),
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
                        // Destination descriptor signs the transfer_id to authorize receiving
                        let recv_witness = DescriptorWitness {
                            stack: vec![recv_sig.serialize().to_vec()],
                        };
                        match deposits_core::descriptor::verify_witness(&dest_deposit.descriptor, &recv_witness, &transfer_id) {
                            Ok(true) => {},
                            Ok(false) => return (false, None, Some("Invalid receive_signature: does not satisfy destination descriptor".to_string())),
                            Err(e) => return (false, None, Some(format!("Receive signature verification failed: {}", e))),
                        }
                    }
                }
            }
        }

        // Create and append the operation (amount_msats/fee_msats computed above in fee validation)
        let witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };
        let operation = LedgerOperation::TransferLock {
            nonce,
            source_deposit_id,
            destination_deposit_id,
            amount: amount_msats,
            fee: fee_msats,
            completion_script: completion_script.to_string(),
            timeout_height,
            transfer_id,
            witness,
        };

        // Append operation (applies state changes: deducts balance, adds to locked)
        let t_append = std::time::Instant::now();
        {
            // Commit via staged flow — no state mutation until signing succeeds
            match self.commit_operation(ledger_id, operation).await {
                Ok(_) => {}
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("Failed to commit transfer_lock: {}", e)),
                    );
                }
            }
        }
        let append_elapsed = t_append.elapsed();

        tracing::debug!("Transfer locked: {}", hex::encode(&transfer_id[..8]));
        tracing::debug!("[PROFILE] transfer_lock: {:?}", append_elapsed);
        (
            true,
            Some(
                serde_json::json!({
                    "transfer_id": transfer_id_hex,
                    "amount": amount_msats,
                    "fee": fee_msats,
                    "message": "Transfer locked successfully"
                })
                .to_string(),
            ),
            None,
        )
    }

    /// Process a transfer_complete request - complete a transfer by revealing preimage
    pub(crate) async fn process_transfer_complete_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::types::DescriptorWitness;

        tracing::debug!(
            "Processing transfer_complete request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let preimage_hex = match request.params.get("preimage").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return (false, None, Some("Missing preimage".to_string())),
        };

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse preimage
        let preimage: Vec<u8> = match hex::decode(preimage_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid preimage (must be 32 bytes)".to_string()),
                )
            }
        };

        // Verify the preimage matches the hash in the pending transfer
        let ledger_id = &request.ledger_id;
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", ledger_id)),
                    )
                }
            };
            let ledger = ledger_arc.read().unwrap();

            let pending = match ledger.state.pending_transfers.get(&transfer_id) {
                Some(p) => p,
                None => return (false, None, Some("Pending transfer not found".to_string())),
            };

            // Verify preimage: hash it and check against completion_script
            // completion_script is like "sha256(abc123...)"
            if pending.completion_script.starts_with("sha256(") {
                let expected_hash_hex =
                    &pending.completion_script[7..pending.completion_script.len() - 1];
                let expected_hash = match hex::decode(expected_hash_hex) {
                    Ok(h) => h,
                    Err(_) => {
                        return (
                            false,
                            None,
                            Some("Invalid hash in completion_script".to_string()),
                        )
                    }
                };

                use bitcoin::hashes::{sha256, Hash};
                let actual_hash = sha256::Hash::hash(&preimage);
                if actual_hash.as_byte_array()[..] != expected_hash[..] {
                    return (
                        false,
                        None,
                        Some("Preimage does not match hash".to_string()),
                    );
                }
            } else {
                return (
                    false,
                    None,
                    Some("Only sha256() completion scripts supported".to_string()),
                );
            }
        }

        // Capture pending transfer info before appending (needed for rollback)
        let pending_transfer_backup = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
            let ledger = ledger_arc.read().unwrap();
            ledger.state.pending_transfers.get(&transfer_id).cloned()
        };

        // Create and append the operation
        let script_witness = DescriptorWitness {
            stack: vec![preimage],
        };
        let operation = LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        };

        // Commit via staged flow
        match self.commit_operation(ledger_id, operation).await {
            Ok(_) => {}
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Failed to commit transfer_complete: {}", e)),
                );
            }
        }

        crate::metrics::record_transfer_completed(&request.ledger_id);
        tracing::debug!("Transfer completed: {}", hex::encode(&transfer_id[..8]));
        let (completed_amount, completed_fee) = pending_transfer_backup
            .as_ref()
            .map(|p| (p.amount, p.fee))
            .unwrap_or((0, 0));
        (
            true,
            Some(
                serde_json::json!({
                    "transfer_id": transfer_id_hex,
                    "amount": completed_amount,
                    "fee": completed_fee,
                    "message": "Transfer completed successfully"
                })
                .to_string(),
            ),
            None,
        )
    }

    /// Process a co-sign request from an operator.
    ///
    /// When another operator wants to update their ledger where we are a quorum member,
    pub(crate) fn format_op_short(op: &LedgerOperation) -> String {
        format!("disc:{}", op.discriminant())
    }

    /// they send us a co-sign request. We validate the update and return our ECDSA signature.
    ///
    /// The signature covers: cosign_data || our_ledger_current_hash
    /// This binds the co-signature to the current state of our own ledger.
    pub(crate) async fn process_cosign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;

        let t1_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let t0_us = request
            .params
            .get("t0_us")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        tracing::info!(
            "PROC cosign_update: ledger={}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract sequence_number early — we need it for the freshness check.
        let sequence_number = match request
            .params
            .get("sequence_number")
            .and_then(|v| v.as_u64())
        {
            Some(seq) => seq,
            None => {
                return (
                    false,
                    None,
                    Some("Missing sequence_number parameter".to_string()),
                )
            }
        };

        // Apply piggybacked updates before freshness check.
        // The requester includes the previous signed update (seq N-1) so we can
        // catch up inline without waiting for relay delivery.
        if let Some(prev_arr) = request
            .params
            .get("previous_updates")
            .and_then(|v| v.as_array())
        {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let mut applied = 0usize;
            for item in prev_arr {
                if let Some(b64) = item.as_str() {
                    if let Ok(tlv) = BASE64.decode(b64) {
                        if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv) {
                            self.handler.insert_event(&update);
                            let ledgers = self.handler.ledgers.lock().unwrap();
                            if let Some(arc) = ledgers.get(&request.ledger_id) {
                                let mut ledger = arc.write().unwrap();
                                if update.sequence_number == ledger.next_sequence()
                                    && update.previous_hash == ledger.tail_hash()
                                {
                                    // Apply state changes so our state stays current with history
                                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                                        let _ = ledger.apply_state_changes(&op);
                                    }
                                    ledger.state.sequence = update.sequence_number;
                                    ledger.state.chain_tip_hash = update.chain_hash();
                                    ledger.history.push(update);
                                    applied += 1;
                                }
                            }
                        }
                    }
                }
            }
            if applied > 0 {
                self.catch_up_ledger_from_event_store(&request.ledger_id);
                tracing::debug!(
                    "Applied {} piggybacked updates for {}...",
                    applied,
                    &request.ledger_id[..16.min(request.ledger_id.len())]
                );
            }
        }

        // Freshness check with event-store recovery.
        //
        // If our ledger history is behind the requested sequence, try to catch up
        // from the event store (pure in-memory, no relay I/O) before giving up.
        // This avoids returning "stale" when the event store already has the events
        // but the ledger history hasn't been updated yet.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                    return (
                        false,
                        None,
                        Some(format!(
                            "Ledger {}... in dispute state {:?}",
                            &request.ledger_id[..16.min(request.ledger_id.len())],
                            ledger.state.dispute_state
                        )),
                    );
                }
                let local_seq = ledger.next_sequence();
                if local_seq < sequence_number {
                    // Release locks before attempting recovery
                    drop(ledger);
                    drop(ledgers);

                    // Try to catch up from event store (no relay I/O)
                    let caught_up = self.catch_up_ledger_from_event_store(&request.ledger_id);
                    if caught_up > 0 {
                        metrics::record_cosign_freshness_recovery("recovered");
                        tracing::info!(
                            "Cosign freshness: caught up {} events from event store for ledger {}...",
                            caught_up, &request.ledger_id[..16.min(request.ledger_id.len())],
                        );
                    }

                    // Re-check after catch-up
                    let still_stale = {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        ledgers
                            .get(&request.ledger_id)
                            .map(|arc| {
                                let l = arc.read().unwrap();
                                l.next_sequence() < sequence_number
                            })
                            .unwrap_or(true)
                    };

                    if still_stale {
                        // Still behind after event store catch-up + pre-cosign channel drain.
                        // Queue for background relay fetch; clear the per-ledger cooldown so
                        // the next reload-loop iteration (2-3s) fires immediately instead of
                        // waiting up to 30s. The operator will retry (3 attempts × 500ms),
                        // giving the background fetch time to catch up.
                        metrics::record_cosign_freshness_recovery("stale");
                        metrics::record_pre_cosign_drain(0, false);
                        self.stale_joined_ledgers
                            .lock()
                            .unwrap()
                            .insert(request.ledger_id.clone());
                        // Reset relay-fetch cooldown so next reload cycle fetches immediately.
                        self.last_relay_fetch_times
                            .lock()
                            .unwrap()
                            .remove(&request.ledger_id);
                        let current_len = {
                            let ledgers = self.handler.ledgers.lock().unwrap();
                            ledgers
                                .get(&request.ledger_id)
                                .map(|arc| arc.read().unwrap().next_sequence())
                                .unwrap_or(0)
                        };
                        tracing::info!(
                            "Cosign stale: have {}, need {} for {}...",
                            current_len,
                            sequence_number,
                            &request.ledger_id[..16.min(request.ledger_id.len())]
                        );
                        return (
                            false,
                            None,
                            Some(format!(
                                "Stale: have seq {}, need {}",
                                current_len, sequence_number
                            )),
                        );
                    }
                }
            }
        }

        let cosign_data_hex = match request
            .params
            .get("cosign_data_hex")
            .and_then(|v| v.as_str())
        {
            Some(hex) => hex.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing cosign_data_hex parameter".to_string()),
                )
            }
        };

        let current_hash_hex = match request
            .params
            .get("current_hash_hex")
            .and_then(|v| v.as_str())
        {
            Some(hex) => hex.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing current_hash_hex parameter".to_string()),
                )
            }
        };

        // Decode cosign data
        let cosign_data = match hex::decode(&cosign_data_hex) {
            Ok(data) => data,
            Err(e) => return (false, None, Some(format!("Invalid cosign_data_hex: {}", e))),
        };

        // Decode current hash (used for validation logging)
        let _current_hash: [u8; 32] = match hex::decode(&current_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => {
                return (
                    false,
                    None,
                    Some("current_hash_hex must be 32 bytes".to_string()),
                )
            }
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Invalid current_hash_hex: {}", e)),
                )
            }
        };

        // Find the operator's ledger where we are a quorum member (for sequence validation)
        // Get the target ledger and extract operator/reserves for matching
        let (operator_ledger_arc, target_operator_id, _target_reserves_key) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&request.ledger_id) {
                let ledger = arc.read().unwrap();
                (
                    Some(arc.clone()),
                    Some(ledger.operator_key()),
                    Some(ledger.reserves_key().to_string()),
                )
            } else {
                (None, None, None)
            }
        };

        // If we don't have the ledger locally, get the operator from the request sender
        // The sender of a cosign_update request IS the operator who needs the co-signature
        let target_operator_id = if target_operator_id.is_none() {
            // The request.sender is a Nostr x-only pubkey (32 bytes / 64 hex chars)
            // We need to convert to secp256k1 PublicKey (33 bytes with 02/03 prefix)
            match hex::decode(&request.sender) {
                Ok(x_only_bytes) if x_only_bytes.len() == 32 => {
                    // Convert x-only to compressed pubkey (assume even y-coordinate)
                    let mut compressed = [0u8; 33];
                    compressed[0] = 0x02;
                    compressed[1..].copy_from_slice(&x_only_bytes);
                    match PublicKey::from_slice(&compressed) {
                        Ok(sender_key) => {
                            tracing::debug!(
                                "Using request sender as target operator: {}...",
                                &request.sender[..16]
                            );
                            Some(sender_key)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse sender as pubkey: {}", e);
                            None
                        }
                    }
                }
                _ => {
                    tracing::warn!(
                        "Invalid sender pubkey format: {}",
                        &request.sender[..16.min(request.sender.len())]
                    );
                    None
                }
            }
        } else {
            target_operator_id
        };

        // Note: We don't strictly need target_reserves_key for matching
        // We can match by operator_id alone since each operator has one ledger

        // Validate sequence number if we have local ledger state.
        // sequence_number = operator's history.len() BEFORE pushing the new update
        // (0-indexed: first entry = seq 0).  Our local copy should have the same
        // number of entries as the operator had before appending.
        //
        // Only reject if we're BEHIND the operator (we're missing history they already
        // have). Being AHEAD is fine — Nostr broadcasts arrive at quorum members faster
        // than cosign requests, so at high TPS members are typically 1-2 seqs ahead.
        // The stale recovery block above handles the "we're behind" case; this block
        // is a safety net for exact-match validation only.
        if let Some(ref arc) = operator_ledger_arc {
            let ledger = arc.read().unwrap();
            let expected_seq = ledger.next_sequence();
            if sequence_number > expected_seq {
                tracing::info!(
                    "Cosign seq mismatch: expected {}, got {} for {}...",
                    expected_seq,
                    sequence_number,
                    &request.ledger_id[..16.min(request.ledger_id.len())]
                );
                return (
                    false,
                    None,
                    Some(format!(
                        "Seq mismatch: expected {}, got {}",
                        expected_seq, sequence_number
                    )),
                );
            }

            if let Some(last_update) = ledger.history.last() {
                let prev_hash = last_update.current_hash;
                tracing::trace!(
                    "Validating co-sign for seq {} (prev_hash: {}...)",
                    sequence_number,
                    &hex::encode(&prev_hash[..4])
                );
            }
        }

        // Auto-detect which of OUR ledgers is bound to the requesting ledger.
        // Uses a cache (target_ledger_id → our_member_ledger_key) to avoid the
        // expensive O(N) history TLV-decode scan on every cosign request.
        let member_ledger_hash: [u8; 32] = {
            // Fast path: check cache
            let cached_key = self
                .cosign_member_cache
                .lock()
                .unwrap()
                .get(&request.ledger_id)
                .cloned();

            let member_key =
                if let Some(key) = cached_key {
                    key
                } else {
                    // Cache miss: do the full scan, then cache the result
                    let t_scan = std::time::Instant::now();
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let mut found_key = None;

                    for (ledger_key, arc) in ledgers.iter() {
                        let ledger = arc.read().unwrap();
                        if ledger.operator_key() != self.node_id {
                            continue;
                        }

                        let history_len = ledger.history.len();
                        let jq_count = ledger.state.joined_quorums.len();
                        // Use derived joined_quorums state instead of scanning history
                        let has_join = ledger.state.joined_quorums.iter().any(|jq| {
                            if jq.ledger_id == request.ledger_id {
                                return true;
                            }
                            if let Some(target_op) = &target_operator_id {
                                let jq_x = &jq.operator_id.serialize()[1..];
                                let target_x = &target_op.serialize()[1..];
                                if jq_x == target_x {
                                    return true;
                                }
                            }
                            false
                        });
                        tracing::info!(
                            "cosign scan: ledger={}..., history={}, joined_quorums={}, match={}",
                            &ledger_key[..16.min(ledger_key.len())],
                            history_len,
                            jq_count,
                            has_join
                        );

                        let scan_elapsed = t_scan.elapsed();
                        if scan_elapsed.as_millis() > 0 {
                            tracing::info!(
                                "[PROFILE] cosign QuorumJoin scan (cache miss): {} entries in {:?}",
                                history_len,
                                scan_elapsed
                            );
                        }

                        if has_join {
                            found_key = Some(ledger_key.clone());
                            break;
                        }
                    }
                    drop(ledgers);

                    match found_key {
                        Some(key) => {
                            self.cosign_member_cache
                                .lock()
                                .unwrap()
                                .insert(request.ledger_id.clone(), key.clone());
                            key
                        }
                        None => return (
                            false,
                            None,
                            Some(
                                "No ledger found with QuorumJoin to target - not a quorum member"
                                    .to_string(),
                            ),
                        ),
                    }
                };

            // O(1) hash lookup using the cached member ledger key
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&member_key) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    let hash = ledger
                        .history
                        .last()
                        .map(|u| u.current_hash)
                        .unwrap_or([0u8; 32]);
                    tracing::trace!(
                        "Member ledger {} hash {}...",
                        &member_key[..16.min(member_key.len())],
                        &hex::encode(&hash[..4])
                    );
                    hash
                }
                None => {
                    // Ledger disappeared — invalidate cache entry and fail
                    self.cosign_member_cache
                        .lock()
                        .unwrap()
                        .remove(&request.ledger_id);
                    return (
                        false,
                        None,
                        Some("Member ledger no longer found".to_string()),
                    );
                }
            }
        };

        // Validate the operation before signing.
        //
        // cosign_data = sequence_number (8 LE) || previous_hash (32) || message (TLV)
        // Extract seq, prev_hash, and message. Verify the update chains from our local
        // tip — if it doesn't, we haven't validated the intervening updates and MUST
        // refuse to sign.
        if cosign_data.len() > 40 {
            // Extract prev_hash from cosign_data (bytes 8..40)
            let mut cosign_prev_hash = [0u8; 32];
            cosign_prev_hash.copy_from_slice(&cosign_data[8..40]);

            // Check chain continuity: the update must build on our validated tip
            if let Some(ref arc) = operator_ledger_arc {
                let ledger = arc.read().unwrap();
                let our_tip = ledger.tail_hash();
                if sequence_number == ledger.next_sequence() && cosign_prev_hash != our_tip {
                    tracing::warn!(
                        "Cosign REFUSED: prev_hash mismatch at seq {} — update chains from {} but our tip is {}",
                        sequence_number,
                        &hex::encode(cosign_prev_hash)[..16],
                        &hex::encode(our_tip)[..16],
                    );
                    return (
                        false,
                        None,
                        Some(
                            "Chain mismatch: update prev_hash doesn't match our validated tip"
                                .to_string(),
                        ),
                    );
                }
            }

            let message_bytes = &cosign_data[40..]; // skip 8 (seq) + 32 (prev_hash)
            match LedgerOperation::tlv_decode(message_bytes) {
                Ok(operation) => {
                    // Validate against local ledger state
                    if let Some(ref arc) = operator_ledger_arc {
                        let ledger = arc.read().unwrap();
                        // Try applying the operation to a clone to check validity
                        match ledger.state.apply(&operation) {
                            Ok(_) => {
                                tracing::debug!(
                                    "Cosign validation passed: seq={} op={}",
                                    sequence_number,
                                    Self::format_op_short(&operation)
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Cosign validation FAILED: seq={} op={} error={}",
                                    sequence_number,
                                    Self::format_op_short(&operation),
                                    e
                                );
                                return (
                                    false,
                                    None,
                                    Some(format!("Operation validation failed: {}", e)),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Cosign: failed to decode operation TLV: {}", e);
                    return (
                        false,
                        None,
                        Some(format!("Failed to decode operation: {}", e)),
                    );
                }
            }
        } else {
            tracing::warn!(
                "Cosign: cosign_data too short ({} bytes)",
                cosign_data.len()
            );
            return (false, None, Some("cosign_data too short".to_string()));
        }

        // Build tagged hash following BIP-340 convention:
        // sha256(sha256(tag) || sha256(tag) || data)
        // This provides domain separation and prevents cross-protocol attacks
        let tag = b"deposits/cosign";
        let tag_hash = sha256::Hash::hash(tag);

        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&cosign_data);
        tagged_input.extend_from_slice(&member_ledger_hash);

        let hash = sha256::Hash::hash(&tagged_input);

        // Sign with Schnorr (BIP-340)
        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_bytes = sig.serialize();

        tracing::debug!(
            "Co-signed update seq={} for ledger {}... (member_ledger_hash: {}...)",
            sequence_number,
            &request.ledger_id[..16],
            &hex::encode(&member_ledger_hash[..4])
        );

        // Return the signature, our pubkey, and our ledger hash
        let t2_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let result = serde_json::json!({
            "cosign_signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "sequence_number": sequence_number,
            "member_ledger_hash_hex": hex::encode(member_ledger_hash),
            "t0_us": t0_us,
            "t1_recv_us": t1_us,
            "t2_send_us": t2_us,
        });

        if t0_us > 0 {
            tracing::info!(
                "[COSIGN-TRACE] seq={} relay_in={}us process={}us",
                sequence_number,
                t1_us.saturating_sub(t0_us),
                t2_us.saturating_sub(t1_us)
            );
        }

        (true, Some(result.to_string()), None)
    }

    /// Process a cosign_offer request from an operator.
    ///
    /// This is called by quorum members when an operator needs a co-signature
    /// on a deposit offer. The co-signature proves the operator has valid
    /// quorum backing, preventing rogue former operators from creating offers
    /// after custody recovery.
    ///
    /// Params:
    /// - offer_id: hex-encoded 32-byte offer ID
    /// - operator_id: hex-encoded compressed public key of the operator
    /// - funding_address: the Bitcoin address for the deposit
    /// - deadline_block: block height when offer expires
    pub(crate) async fn process_cosign_offer_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;
        use std::str::FromStr;

        tracing::info!(
            "Processing cosign_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Refuse to co-sign if the ledger is in a disputed state.
        // Don't block on reimport — the background sync will catch up.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                    tracing::warn!(
                        "Refusing to cosign offer for ledger {} - dispute state: {:?}",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        ledger.state.dispute_state
                    );
                    return (
                        false,
                        None,
                        Some(format!(
                            "Ledger is in {:?} state - cannot co-sign offers",
                            ledger.state.dispute_state
                        )),
                    );
                }
            }
        }

        // Extract required parameters
        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };

        let offer_id: [u8; 32] = match hex::decode(&offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => return (false, None, Some("offer_id must be 32 bytes".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid offer_id hex: {}", e))),
        };

        let operator_id_hex = match request.params.get("operator_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing operator_id parameter".to_string()),
                )
            }
        };

        let operator_id = match PublicKey::from_str(&operator_id_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid operator_id: {}", e))),
        };

        let funding_address = match request
            .params
            .get("funding_address")
            .and_then(|v| v.as_str())
        {
            Some(addr) => addr.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing funding_address parameter".to_string()),
                )
            }
        };

        let deadline_block = match request
            .params
            .get("deadline_block")
            .and_then(|v| v.as_u64())
        {
            Some(b) => b as u32,
            None => {
                return (
                    false,
                    None,
                    Some("Missing deadline_block parameter".to_string()),
                )
            }
        };

        // Get the target operator from the request sender
        let target_operator_id = match hex::decode(&request.sender) {
            Ok(x_only_bytes) if x_only_bytes.len() == 32 => {
                // Convert x-only to compressed pubkey (assume even y-coordinate)
                let mut compressed = [0u8; 33];
                compressed[0] = 0x02;
                compressed[1..].copy_from_slice(&x_only_bytes);
                PublicKey::from_slice(&compressed).ok()
            }
            _ => None,
        };

        // Auto-detect which of OUR ledgers is bound to the requesting ledger.
        // Match on ledger_id (stable across custody transfers) with fallback
        // to operator x-coord match.
        let member_ledger_hash: [u8; 32] = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found_hash = None;

            for (_ledger_id, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();

                // Only look at ledgers where we are the operator
                if ledger.operator_key() != self.node_id {
                    continue;
                }

                // Use derived joined_quorums state instead of scanning history
                let has_join = ledger.state.joined_quorums.iter().any(|jq| {
                    if jq.ledger_id == request.ledger_id {
                        return true;
                    }
                    if let Some(target_op) = &target_operator_id {
                        let jq_x = &jq.operator_id.serialize()[1..];
                        let target_x = &target_op.serialize()[1..];
                        if jq_x == target_x {
                            return true;
                        }
                    }
                    false
                });

                if has_join {
                    found_hash = Some(
                        ledger
                            .history
                            .last()
                            .map(|u| u.current_hash)
                            .unwrap_or([0u8; 32]),
                    );
                    break;
                }
            }

            match found_hash {
                Some(h) => h,
                None => {
                    return (
                        false,
                        None,
                        Some(
                            "No ledger found with QuorumJoin to target - not a quorum member"
                                .to_string(),
                        ),
                    )
                }
            }
        };

        // Build the offer signing data
        let signing_data = Self::build_offer_signing_data(
            &request.ledger_id,
            &offer_id,
            &operator_id,
            &funding_address,
            deadline_block,
        );

        // Build tagged hash following BIP-340 convention
        let tag = b"deposits/offer_cosign";
        let tag_hash = sha256::Hash::hash(tag);

        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&signing_data);
        tagged_input.extend_from_slice(&member_ledger_hash);

        let hash = sha256::Hash::hash(&tagged_input);

        // Sign with Schnorr (BIP-340)
        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_bytes = sig.serialize();

        tracing::info!(
            "Co-signed offer {} for ledger {}... (member_ledger_hash: {}...)",
            &offer_id_hex[..16],
            &request.ledger_id[..16],
            &hex::encode(&member_ledger_hash[..4])
        );

        // Return the signature, our pubkey, and our ledger hash
        let result = serde_json::json!({
            "signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "member_ledger_hash_hex": hex::encode(member_ledger_hash),
        });

        (true, Some(result.to_string()), None)
    }

    pub(crate) async fn process_cosign_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;

        tracing::info!(
            "Processing cosign_invoice request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return (false, None, Some("Missing payment_hash".to_string())),
        };
        let deposit_id_hex = match request.params.get("deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d.to_string(),
            None => return (false, None, Some("Missing deposit_id".to_string())),
        };
        let amount_msat = match request.params.get("amount_msat").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_msat".to_string())),
        };

        let payment_hash: [u8; 32] = match hex::decode(&payment_hash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        };
        let deposit_id: [u8; 16] = match hex::decode(&deposit_id_hex) {
            Ok(b) if b.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                a
            }
            _ => return (false, None, Some("Invalid deposit_id".to_string())),
        };

        // Find our member ledger hash (same lookup as cosign_offer)
        let member_ledger_hash: [u8; 32] = {
            let cached_key = self
                .cosign_member_cache
                .lock()
                .unwrap()
                .get(&request.ledger_id)
                .cloned();
            let member_key = if let Some(key) = cached_key {
                key
            } else {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found_key = None;
                for (ledger_key, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    if ledger.operator_key() != self.node_id {
                        continue;
                    }
                    let has_join = ledger
                        .state
                        .joined_quorums
                        .iter()
                        .any(|jq| jq.ledger_id == request.ledger_id);
                    if has_join {
                        found_key = Some(ledger_key.clone());
                        break;
                    }
                }
                drop(ledgers);
                match found_key {
                    Some(key) => {
                        self.cosign_member_cache
                            .lock()
                            .unwrap()
                            .insert(request.ledger_id.clone(), key.clone());
                        key
                    }
                    None => return (false, None, Some("Not a quorum member".to_string())),
                }
            };
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&member_key) {
                Some(arc) => arc
                    .read()
                    .unwrap()
                    .history
                    .last()
                    .map(|u| u.current_hash)
                    .unwrap_or([0u8; 32]),
                None => return (false, None, Some("Member ledger not found".to_string())),
            }
        };

        // Build tagged hash: SHA256(tag || tag || signing_data || member_ledger_hash)
        let signing_data = Self::build_invoice_signing_data(
            &request.ledger_id,
            &payment_hash,
            &deposit_id,
            amount_msat,
        );
        let tag = b"deposits/invoice_cosign";
        let tag_hash = sha256::Hash::hash(tag);
        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&signing_data);
        tagged_input.extend_from_slice(&member_ledger_hash);
        let hash = sha256::Hash::hash(&tagged_input);

        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        tracing::info!(
            "Co-signed invoice {} for ledger {}...",
            &payment_hash_hex[..16],
            &request.ledger_id[..16]
        );

        let result = serde_json::json!({
            "cosign_signature": hex::encode(sig.serialize()),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "cosigner_ledger_hash": hex::encode(member_ledger_hash),
        });
        (true, Some(result.to_string()), None)
    }

    pub(crate) async fn process_custody_transfer_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::secp256k1::{Keypair, Message};
        use deposits_core::SignedLedgerUpdate;
        use nostr_sdk::prelude::*;

        tracing::info!("Processing custody_transfer_sign request...");

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
        let sighash_bytes: [u8; 32] = match hex::decode(&sighash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
        };

        // Parse new custodian (validated but not directly used in signing)
        let _new_custodian: PublicKey = match new_custodian_hex.parse() {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid new_custodian: {}", e))),
        };

        tracing::info!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
        tracing::info!(
            "    New custodian: {}...",
            &new_custodian_hex[..16.min(new_custodian_hex.len())]
        );
        tracing::info!(
            "    Violation: {}",
            &violation_details[..50.min(violation_details.len())]
        );

        // Use the node's operator key
        let secp = &self.secp;
        let secret_key = self.wallet.operator_secret();
        let keypair = Keypair::from_secret_key(secp, &secret_key);
        let our_pubkey = self.node_id;

        tracing::info!("    Our key: {}...", &our_pubkey.to_string()[..16]);

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id.as_str())],
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

        tracing::info!("    Violation verified at seq {}", validated_sequence + 1);

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

        tracing::info!("    Verified: we are a quorum member");

        // Sign the sighash
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);
        let signature_bytes = signature.serialize();

        tracing::info!(
            "    Signed sighash: {}...",
            &hex::encode(&signature_bytes[..4])
        );

        // Return the signature
        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
            "signature": hex::encode(signature_bytes),
            "sighash": sighash_hex,
        });

        (true, Some(result.to_string()), None)
    }

    pub(crate) async fn process_confiscation_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::Message;

        tracing::info!(
            "Processing confiscation_sign request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract sighash from request params
        let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("Missing sighash parameter".to_string())),
        };

        let sighash_bytes: [u8; 32] = match hex::decode(sighash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return (false, None, Some("Invalid sighash format".to_string())),
        };

        // Check if we have an armed marker for this ledger (meaning we're participating in the dispute)
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        let armed_marker = self
            .data_dir
            .join(format!("custody_armed_{}.marker", ledger_prefix));

        if !armed_marker.exists() {
            return (false, None, Some("Not armed for this dispute".to_string()));
        }

        // Sign the sighash
        let secp = &self.secp;
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);

        let _our_pubkey = keypair.public_key();
        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
            "signature": hex::encode(signature.serialize()),
        });

        tracing::info!(
            "Signed confiscation sighash for ledger {}...",
            ledger_prefix
        );
        (true, Some(result.to_string()), None)
    }

    pub(crate) async fn process_custodian_query_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        // Get ledger
        let (reserves_id, ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let custodian_hex = hex::encode(ledger.operator_key().serialize());
        let attester_hex = hex::encode(self.node_id.serialize());

        let result = serde_json::json!({
            "status": "SUCCESS",
            "custodian": custodian_hex,
            "attester": attester_hex,
            "reserves_id": reserves_id,
            "ledger_id": ledger.ledger_id_hex(),
        });
        (true, Some(result.to_string()), None)
    }

    // ========================================================================
    // Daemon-mediated CLI request handlers
    // ========================================================================

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

    pub(crate) async fn process_quorum_add_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing quorum_add request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let member_pubkey_hex = match request.params.get("member_pubkey").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_pubkey parameter".to_string()),
                )
            }
        };
        let member_ledger_id = match request
            .params
            .get("member_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_ledger_id parameter".to_string()),
                )
            }
        };

        let quorum_member = match PublicKey::from_str(member_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid member_pubkey: {}", e))),
        };

        if member_ledger_id.len() != 64 || !member_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("member_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
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

        // Request consent from the member — they sign and record QuorumJoin
        let consent_signature = match self.request_consent(&member_ledger_id, &ledger_id).await {
            Ok(result) => result.consent_signature,
            Err(e) => {
                tracing::error!("Consent request failed: {}", e);
                return (false, None, Some(format!("Member consent failed: {}", e)));
            }
        };

        // Extract fee limits the member is imposing (from their advertisement)
        let min_fee_bps = request
            .params
            .get("min_fee_bps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        let min_fee_fixed = request.params.get("min_fee_fixed").and_then(|v| v.as_u64());
        let max_fee_period = request
            .params
            .get("max_fee_period")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        // Extract membership duration from request
        let membership_until = request
            .params
            .get("membership_until")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        match self
            .add_quorum_member(
                &ledger_id,
                quorum_member,
                &member_ledger_id,
                consent_signature,
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                membership_until,
            )
            .await
        {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "member": member_pubkey_hex,
                    "member_ledger_id": member_ledger_id,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_add failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    pub(crate) async fn process_quorum_remove_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        let member_pubkey_hex = match request.params.get("member_pubkey").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_pubkey parameter".to_string()),
                )
            }
        };

        let quorum_member = match PublicKey::from_str(member_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid member_pubkey: {}", e))),
        };

        let ledger_id = &request.ledger_id;

        tracing::info!(
            "Removing quorum member {}... from ledger {}...",
            &member_pubkey_hex[..16.min(member_pubkey_hex.len())],
            &ledger_id[..16.min(ledger_id.len())]
        );

        let operation = LedgerOperation::QuorumRemoveMember {
            quorum_member,
            operator_signature: [0u8; 64], // filled by commit_operation
        };

        match self.commit_operation(ledger_id, operation).await {
            Ok(_) => {
                tracing::info!(
                    "Quorum member removed: {}...",
                    &member_pubkey_hex[..16.min(member_pubkey_hex.len())]
                );
                let result = serde_json::json!({ "removed": member_pubkey_hex });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (
                false,
                None,
                Some(format!("Failed to remove quorum member: {}", e)),
            ),
        }
    }

    pub(crate) async fn process_quorum_join_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing quorum_join request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let target_operator_hex = match request
            .params
            .get("target_operator")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing target_operator parameter".to_string()),
                )
            }
        };
        let target_ledger_id = match request
            .params
            .get("target_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing target_ledger_id parameter".to_string()),
                )
            }
        };
        let membership_expires = match request
            .params
            .get("membership_expires")
            .and_then(|v| v.as_u64())
        {
            Some(v) => v as u32,
            None => {
                return (
                    false,
                    None,
                    Some("Missing membership_expires parameter".to_string()),
                )
            }
        };

        let target_operator = match PublicKey::from_str(target_operator_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid target_operator: {}", e))),
        };

        if target_ledger_id.len() != 64 || !target_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("target_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Resolve our ledger_id
        let our_ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
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

        // Sign consent: COLLATERAL_CONSENT || operator_pubkey(33 bytes) || ledger_id(string bytes)
        let _signature = {
            use bitcoin::hashes::{sha256, Hash};
            use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

            let mut sign_content = Vec::new();
            sign_content.extend_from_slice(b"COLLATERAL_CONSENT");
            sign_content.extend_from_slice(&target_operator.serialize());
            sign_content.extend_from_slice(target_ledger_id.as_bytes());

            let hash = sha256::Hash::hash(&sign_content);
            let secp_msg = Message::from_digest(hash.to_byte_array());
            let secp = Secp256k1::new();
            let keypair = Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr_no_aux_rand(&secp_msg, &keypair);
            sig.serialize()
        };

        match self
            .record_quorum_join(
                &our_ledger_id,
                target_operator,
                &target_ledger_id,
                membership_expires,
            )
            .await
        {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "target_operator": target_operator_hex,
                    "target_ledger_id": target_ledger_id,
                    "membership_expires": membership_expires,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_join failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Handle a consent_request from an operator wanting us to join their quorum.
    ///
    /// Auto-consents: signs the consent content, records QuorumJoin on our ledger,
    /// and returns the signature so the operator can record QuorumAddMember.
    pub(crate) async fn process_consent_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing consent_request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let operator_pubkey_hex = match request
            .params
            .get("operator_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing operator_pubkey parameter".to_string()),
                )
            }
        };
        let operator_ledger_id = match request
            .params
            .get("operator_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing operator_ledger_id parameter".to_string()),
                )
            }
        };

        let operator_pubkey = match PublicKey::from_str(operator_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid operator_pubkey: {}", e))),
        };

        if operator_ledger_id.len() != 64
            || !operator_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("operator_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Sign consent: COLLATERAL_CONSENT || operator_pubkey(33 bytes) || ledger_id(string bytes)
        let mut sign_content = Vec::new();
        sign_content.extend_from_slice(b"COLLATERAL_CONSENT");
        sign_content.extend_from_slice(&operator_pubkey.serialize());
        sign_content.extend_from_slice(operator_ledger_id.as_bytes());

        let signature = {
            use bitcoin::hashes::{sha256, Hash};
            use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

            let hash = sha256::Hash::hash(&sign_content);
            let secp_msg = Message::from_digest(hash.to_byte_array());
            let secp = Secp256k1::new();
            let keypair = Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr_no_aux_rand(&secp_msg, &keypair);
            sig.serialize()
        };

        // Record QuorumJoin on our own ledger
        let our_ledger_id = request.ledger_id.clone();
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let membership_expires = current_block + 1000; // ~1 week at 10 min/block

        match self
            .record_quorum_join(
                &our_ledger_id,
                operator_pubkey,
                &operator_ledger_id,
                membership_expires,
            )
            .await
        {
            Ok(_event_id) => {
                tracing::info!(
                    "Consent granted: recorded QuorumJoin for operator {}... on our ledger {}...",
                    &operator_pubkey_hex[..16.min(operator_pubkey_hex.len())],
                    &our_ledger_id[..16]
                );
                let result = serde_json::json!({
                    "status": "CONSENT_GRANTED",
                    "consent_signature": hex::encode(signature),
                    "membership_expires": membership_expires,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("Failed to record QuorumJoin: {}", e);
                (
                    false,
                    None,
                    Some(format!("Failed to record QuorumJoin: {}", e)),
                )
            }
        }
    }

    pub(crate) async fn process_quorum_begin_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing quorum_begin request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
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

        // Reload reserves from disk (CLI may have created them after daemon started)
        if let Err(e) = self.wallet.reload_reserves_from_disk() {
            tracing::warn!("Failed to reload reserves from disk: {}", e);
        }

        // Sync wallet to see current UTXOs
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed before quorum_begin: {}", e);
        }

        match self.rotate_reserves_to_quorum(&ledger_id) {
            Ok(result) => {
                // Broadcast the update to Nostr
                if let Err(e) = self.broadcast_last_update(&ledger_id).await {
                    tracing::warn!("Failed to broadcast reserves rotation: {}", e);
                }

                let response = serde_json::json!({
                    "status": "SUCCESS",
                    "txid": result.txid,
                    "new_address": result.new_address,
                    "amount_sats": result.amount_sats,
                    "quorum_member_count": result.quorum_member_count,
                    "quorum_expiry": result.quorum_expiry,
                    "ledger_hash": hex::encode(&result.ledger_hash[..8]),
                });
                (true, Some(response.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_begin failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Process a resync request from a quorum member asking us to re-broadcast
    /// ledger updates from a given sequence number. This enables post-restart
    /// recovery when the relay has evicted old events.
    pub(crate) async fn process_resync_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        let from_seq = request
            .params
            .get("from_seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        tracing::info!(
            "Processing resync request for ledger {}... from_seq={}",
            &request.ledger_id[..16.min(request.ledger_id.len())],
            from_seq,
        );

        // Get the ledger history
        let updates: Vec<deposits_core::SignedLedgerUpdate> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&request.ledger_id) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    ledger
                        .history
                        .iter()
                        .filter(|u| u.sequence_number >= from_seq)
                        .cloned()
                        .collect()
                }
                None => {
                    return (
                        false,
                        None,
                        Some(format!(
                            "Ledger not found: {}...",
                            &request.ledger_id[..16.min(request.ledger_id.len())]
                        )),
                    );
                }
            }
        };

        if updates.is_empty() {
            let response = serde_json::json!({
                "rebroadcast_count": 0,
                "from_seq": from_seq,
                "through_seq": from_seq,
                "total_available": 0,
                "has_more": false,
            });
            return (true, Some(response.to_string()), None);
        }

        let total_available = updates.len();
        let batch: Vec<_> = updates.into_iter().take(Self::RESYNC_BATCH_CAP).collect();
        let first_seq = batch.first().map(|u| u.sequence_number).unwrap_or(from_seq);
        let last_seq = batch.last().map(|u| u.sequence_number).unwrap_or(from_seq);

        let mut rebroadcast_count = 0usize;
        for (i, update) in batch.iter().enumerate() {
            match self.nostr.broadcast_ledger_update(update).await {
                Ok(_) => rebroadcast_count += 1,
                Err(e) => {
                    tracing::warn!(
                        "Resync broadcast failed at seq {}: {}",
                        update.sequence_number,
                        e,
                    );
                    break;
                }
            }
            // Yield every 10 broadcasts to avoid starving other tasks
            if (i + 1) % 10 == 0 {
                tokio::task::yield_now().await;
            }
        }

        let has_more = total_available > Self::RESYNC_BATCH_CAP;
        tracing::info!(
            "Resync: re-broadcast {} updates (seq {}..{}) for ledger {}... ({} total available, has_more={})",
            rebroadcast_count, first_seq, last_seq,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            total_available, has_more,
        );

        let response = serde_json::json!({
            "rebroadcast_count": rebroadcast_count,
            "from_seq": first_seq,
            "through_seq": last_seq,
            "total_available": total_available,
            "has_more": has_more,
        });
        (true, Some(response.to_string()), None)
    }

    /// Return health status of the running daemon: relay connections, subscriptions, ledgers.
    pub(crate) async fn process_health_status_request(
        &self,
    ) -> (bool, Option<String>, Option<String>) {
        let mut relays = Vec::new();

        // Main client relays
        for (url, relay) in self.nostr.client().relays().await {
            let stats = relay.stats();
            relays.push(serde_json::json!({
                "url": url.to_string(),
                "status": format!("{:?}", relay.status()),
                "latency_ms": stats.latency().map(|d| d.as_millis() as u64),
                "attempts": stats.attempts(),
                "success": stats.success(),
                "success_rate": format!("{:.1}%", stats.success_rate() * 100.0),
                "bytes_sent": stats.bytes_sent(),
                "bytes_received": stats.bytes_received(),
                "connected_at": stats.connected_at().as_u64(),
            }));
        }

        // Slow client relays
        let mut slow_relays = Vec::new();
        let fetch = self.nostr.fetch_client();
        if !std::ptr::eq(fetch, self.nostr.client()) {
            for (url, relay) in fetch.relays().await {
                let stats = relay.stats();
                slow_relays.push(serde_json::json!({
                    "url": url.to_string(),
                    "status": format!("{:?}", relay.status()),
                    "bytes_sent": stats.bytes_sent(),
                    "bytes_received": stats.bytes_received(),
                }));
            }
        }

        // Subscriptions
        let subs = self.nostr.client().subscriptions().await;

        // Pending invoices
        let pending_invoices = self.pending_invoices.lock().unwrap().len();

        // Ledgers
        let ledger_info: Vec<serde_json::Value> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .map(|(lid, arc)| {
                    let l = arc.read().unwrap();
                    serde_json::json!({
                        "id": &lid[..16.min(lid.len())],
                        "role": format!("{:?}", l.role),
                        "sequence": l.state.sequence,
                        "deposits": l.state.deposits.len(),
                        "quorum_members": l.state.quorum_members.len(),
                    })
                })
                .collect()
        };

        let result = serde_json::json!({
            "relays": relays,
            "slow_relays": slow_relays,
            "subscriptions": subs.len(),
            "pending_invoices": pending_invoices,
            "ledgers": ledger_info,
            "uptime_secs": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });

        (true, Some(result.to_string()), None)
    }

    // ========================================================================
    /// Health ping: create a dummy FeeCollect(0) update, cosign it via the daemon's
    /// live connections, measure RTT, then discard the update.
    pub(crate) async fn process_health_ping_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::messages::LedgerOperation;

        let ledger_id = &request.ledger_id;

        // Check if quorum is active
        if !self.is_quorum_active(ledger_id) {
            return (false, None, Some("No active quorum".to_string()));
        }

        // Find a deposit for the dummy fee collect
        let deposit_id = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => {
                    let l = arc.read().unwrap();
                    match l.state.deposits.keys().next() {
                        Some(id) => *id,
                        None => return (false, None, Some("No deposits on ledger".to_string())),
                    }
                }
                None => return (false, None, Some("Ledger not found".to_string())),
            }
        };

        let block_height = self.wallet.get_block_height().unwrap_or(0);
        let op = LedgerOperation::FeeCollect {
            deposit_id,
            amount: 0,
            block_height,
        };

        let start = std::time::Instant::now();
        match self.commit_operation(ledger_id, op).await {
            Ok(_) => {
                let total_ms = start.elapsed().as_secs_f64() * 1000.0;
                let cosigner = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    ledgers
                        .get(ledger_id)
                        .and_then(|arc| {
                            let l = arc.read().unwrap();
                            l.history.last().and_then(|u| {
                                u.cosigner_pubkey.map(|pk| hex::encode(pk.serialize()))
                            })
                        })
                        .unwrap_or_default()
                };
                let result = serde_json::json!({
                    "cosigner": cosigner,
                    "cosign_ms": total_ms,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                (
                    false,
                    None,
                    Some(format!("Cosign failed ({:.0}ms): {}", ms, e)),
                )
            }
        }
    }

    // ========================================================================
    // Admin handlers — gift-wrapped requests only, gated by check_admin_authorized.
    // These expose the filesystem-only bootstrap operations as Nostr actions so
    // the daemon can run continuously and remote admins can drive them.
    // ========================================================================

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
