//! Deposits request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

/// Parse the `deposit_id` field (32 hex chars = 16 bytes) from a Nostr
/// request's `params`. Used by every handler that operates on an
/// existing deposit — `make_invoice`, `pay_invoice`, `make_offer`
/// (existing-deposit branch), `balance_query`, `deposit_credit`,
/// `withdraw`, `offer_status`, etc. Returns the canonical id-bytes or
/// a human-readable error suitable for the request response.
pub(super) fn parse_deposit_id_param(
    request: &crate::nostr::LedgerRequest,
) -> Result<deposits_core::types::DepositId, String> {
    let s = request
        .params
        .get("deposit_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing deposit_id parameter".to_string())?;
    let bytes = hex::decode(s)
        .map_err(|_| format!("Invalid deposit_id (must be 32-char hex, got {:?})", s))?;
    if bytes.len() != 16 {
        return Err(format!(
            "Invalid deposit_id length: expected 16 bytes, got {}",
            bytes.len()
        ));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Parse the `descriptor` field from a Nostr request's `params`. Used
/// by `deposit_open`, `make_offer`, `make_invoice`, and `pay_invoice` —
/// any handler whose semantics need the full miniscript expression
/// (either to instantiate a deposit, or to verify a witness against
/// the descriptor). Returns the descriptor string + its computed
/// `deposit_id`.
pub(super) fn parse_descriptor_param(
    request: &crate::nostr::LedgerRequest,
) -> Result<(String, deposits_core::types::DepositId), String> {
    let descriptor = request
        .params
        .get("descriptor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing descriptor parameter".to_string())?
        .to_string();
    if descriptor.is_empty() {
        return Err("Empty descriptor".to_string());
    }
    let id = deposits_core::types::compute_deposit_id(&descriptor);
    Ok((descriptor, id))
}

/// Verify a [`deposits_core::dep16::ReceiveWitness`]-shaped JSON value against a deposit's
/// descriptor. Routes through `Dep16Authorizer::authorize_receive` — the wallet signed the
/// dep-17 preimage of `receive_op(deposit_id, nonce, expiry, transfer_id=None)`, the node
/// reconstructs that preimage and verifies. Used by `make_offer` and `make_invoice` whenever
/// the deposit (or proposed deposit) has `receive_requires_sig`.
///
/// `chain_tip` is the operator's current height; once phase 3 per-deposit nonce/expiry lands
/// it'll feed the expiry/nonce gating.
pub(super) fn verify_receive_witness(
    descriptor: &str,
    deposit_id: &deposits_core::types::DepositId,
    request: &crate::nostr::LedgerRequest,
    chain_tip: u32,
) -> Result<(), String> {
    let witness_value = request
        .params
        .get("receive_witness")
        .ok_or_else(|| "Deposit requires receive_witness".to_string())?;
    let witness: deposits_core::dep16::ReceiveWitness =
        serde_json::from_value(witness_value.clone())
            .map_err(|e| format!("Invalid receive_witness shape: {}", e))?;
    if witness.expiry < chain_tip {
        return Err(format!(
            "receive_witness expired (expiry={} < chain_tip={})",
            witness.expiry, chain_tip
        ));
    }
    let authorizer = deposits_core::dep16::Dep16Authorizer::new();
    if authorizer.authorize_receive(descriptor, deposit_id, None, &witness) {
        Ok(())
    } else {
        Err("receive_witness does not satisfy deposit descriptor".to_string())
    }
}

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
                    let attestation_possible = self.attestation_verifier_pubkey.is_some();

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
                                    let domain_list: Vec<String> =
                                        domains.iter().cloned().collect();
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

        // Caller submits a full miniscript descriptor; we compute
        // deposit_id from it. Identity comes from the descriptor,
        // not from a single pubkey, so multi() / or() / etc. work
        // end-to-end.
        let (descriptor, deposit_id) = match parse_descriptor_param(request) {
            Ok(parts) => parts,
            Err(msg) => return (false, None, Some(msg)),
        };

        // Resolve fee minimums. The local operator_policy.json is
        // authoritative when present (set deliberately by `ledger advertise`).
        // Fall back to the relay-published advertisement only if the operator
        // hasn't written a policy yet — this is the fresh-bootstrap window
        // before the operator has set deliberate fees. After they have,
        // forgetting CLI flags on a re-advertise no longer silently zeros
        // the enforcement floor.
        let policy = crate::operator_policy::OperatorPolicy::load(&self.data_dir).unwrap_or(None);

        let (min_annual_bps, min_fixed_per_period, advertisement) = match policy {
            Some(p) => {
                let (bps, fixed) = p.minimum_fees();
                tracing::debug!(
                    "deposit_open: applying operator_policy.json minimums (bps={}, fixed_per_period={})",
                    bps,
                    fixed
                );
                // Synthesize an advertisement-shaped struct from the policy
                // so the existing fall-through code (defaulted FeeStructure
                // for wallets that don't propose explicit fees) keeps working.
                let mut ad = crate::nostr::LedgerAdvertisement::new(
                    request.ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                // Charged-fee defaults for wallets that don't propose explicit
                // fees (the FLOOR is `min_*` above, which stays 0 when unset).
                ad.annual_fee_bps = p.effective_annual_fee_bps();
                ad.annualized_fixed_msats = p.effective_annualized_fixed_msats();
                ad.fee_period_blocks = p.fee_period_blocks.unwrap_or(2016);
                (bps, fixed, ad)
            }
            None => {
                tracing::warn!(
                    "deposit_open: operator_policy.json absent for ledger {} — \
                     falling back to relay advertisement for fee floors",
                    &request.ledger_id[..16]
                );
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
                        // Genuinely unconfigured (no policy, no relay ad): keep the
                        // historical zero floor / zero charged default rather than
                        // fabricating the project fee default in the accept path.
                        // (new() now defaults to the project custody fee.)
                        let mut ad = crate::nostr::LedgerAdvertisement::new(
                            request.ledger_id.clone(),
                            String::new(),
                            String::new(),
                            String::new(),
                        );
                        ad.annual_fee_bps = 0;
                        ad.annualized_fixed_msats = 0;
                        ad
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to fetch advertisement: {}, using zero fee minimums",
                            e
                        );
                        // Unknown config (fetch failed): keep historical zero
                        // floor / zero charged default rather than the project
                        // fee default that new() now carries.
                        let mut ad = crate::nostr::LedgerAdvertisement::new(
                            request.ledger_id.clone(),
                            String::new(),
                            String::new(),
                            String::new(),
                        );
                        ad.annual_fee_bps = 0;
                        ad.annualized_fixed_msats = 0;
                        ad
                    }
                };
                let (bps, fixed) = advertisement.minimum_fees();
                (bps, fixed, advertisement)
            }
        };

        // Extract fee parameters from request OR use advertisement defaults
        let ad_period = if advertisement.fee_period_blocks > 0 {
            advertisement.fee_period_blocks
        } else {
            2016
        };
        // Wire keys mirror the protocol's `FeeStructure` field names
        // exactly. Hard-broken from the previous `fee_fixed` /
        // `fee_bps` / `fee_frequency` shape — wallets sending the old
        // keys will be silently ignored and fall through to the
        // advertisement's defaults.
        let frequency_blocks = request
            .params
            .get("frequency_blocks")
            .and_then(|v| v.as_u64())
            .map(|v| if v > 0 { v as u32 } else { 2016 })
            .unwrap_or(ad_period);

        let fees = if request.params.get("annualized_msats").is_some()
            || request.params.get("annualized_bps").is_some()
        {
            FeeStructure {
                annualized_msats: request
                    .params
                    .get("annualized_msats")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                annualized_bps: request
                    .params
                    .get("annualized_bps")
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
            ad_period,
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
                    "deposit_id": hex::encode(deposit_id),
                    "descriptor": descriptor,
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
                tracing::info!(
                    "Deposit opened: id={} descriptor={}",
                    hex::encode(deposit_id),
                    &descriptor[..32.min(descriptor.len())]
                );
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

        // Caller submits the full miniscript descriptor; we compute
        // deposit_id from it and pass the descriptor through to the
        // offer. Identity comes from the descriptor, so multi() / or() /
        // etc. work end-to-end (no `pk()`-only assumption baked in).
        let (descriptor, deposit_id) = match parse_descriptor_param(request) {
            Ok(parts) => parts,
            Err(msg) => return (false, None, Some(msg)),
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
                // Unconfigured: keep zero floor / zero charged default rather
                // than the project fee default that new() now carries.
                let mut ad = crate::nostr::LedgerAdvertisement::new(
                    resolved_ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                ad.annual_fee_bps = 0;
                ad.annualized_fixed_msats = 0;
                ad
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch advertisement: {}, using zero fee minimums",
                    e
                );
                // Unknown config (fetch failed): keep zero floor / zero charged
                // default rather than the project fee default new() now carries.
                let mut ad = crate::nostr::LedgerAdvertisement::new(
                    resolved_ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                ad.annual_fee_bps = 0;
                ad.annualized_fixed_msats = 0;
                ad
            }
        };

        let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();
        let ad_period = if advertisement.fee_period_blocks > 0 {
            advertisement.fee_period_blocks
        } else {
            2016
        };

        // Extract fee parameters using the canonical `FeeStructure`
        // field names. See the deposit_open handler above for the
        // hard-break note.
        let fees = if request.params.get("annualized_msats").is_some()
            || request.params.get("annualized_bps").is_some()
            || request.params.get("frequency_blocks").is_some()
        {
            let frequency_blocks = request
                .params
                .get("frequency_blocks")
                .and_then(|v| v.as_u64())
                .map(|v| if v > 0 { v as u32 } else { ad_period })
                .unwrap_or(ad_period);

            FeeStructure {
                annualized_msats: request
                    .params
                    .get("annualized_msats")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                annualized_bps: request
                    .params
                    .get("annualized_bps")
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
            ad_period,
        ) {
            return (false, None, Some(format!("Fee validation failed: {}", e)));
        }

        // If the deposit already exists with `receive_requires_sig`,
        // require a `receive_witness` that satisfies the descriptor.
        // The witness covers the deposit_id padded to 32 bytes.
        {
            let needs_witness = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&resolved_ledger_id)
                    .and_then(|ledger_arc| {
                        let ledger = ledger_arc.read().unwrap();
                        ledger
                            .state
                            .deposits
                            .get(&deposit_id)
                            .map(|d| d.receive_requires_sig)
                    })
                    .unwrap_or(false)
            };
            if needs_witness {
                let tip = self.wallet.get_block_height().unwrap_or(0);
                if let Err(msg) = verify_receive_witness(&descriptor, &deposit_id, request, tip) {
                    return (false, None, Some(msg));
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
        if let Some(err) =
            self.check_deposit_balance_limit(&resolved_ledger_id, &deposit_id, max_sats * 1000)
        {
            return (false, None, Some(err));
        }

        // Create the offer using ledger_id (stable across custody transfers)
        match self.create_deposit_offer(
            &resolved_ledger_id,
            &descriptor,
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
    /// - offer_id: hex-encoded 32-byte offer ID (required)
    /// - deposit_id: 32-char hex (16-byte) deposit_id (optional fallback)
    ///
    /// If offer_id is found, returns the offer status.
    /// If offer_id is not found but `deposit_id` is provided, checks if the
    /// deposit exists in the ledger (meaning the offer was completed).
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

        // Optional fallback: caller may pass deposit_id so we can answer
        // "was the offer completed?" by looking the deposit up in the ledger.
        let fallback_deposit_id = parse_deposit_id_param(request).ok();

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
                // Offer not in our tracking. If we have a deposit_id, check
                // if the deposit exists in the ledger (meaning it was funded
                // and completed).
                if let Some(deposit_id) = fallback_deposit_id {
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
    /// - deposit_id: 32-char hex (16-byte) deposit identifier
    ///
    /// Returns the current balance in the ledger (in millisatoshis)
    pub(crate) async fn process_balance_query_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        let deposit_id = match parse_deposit_id_param(request) {
            Ok(id) => id,
            Err(msg) => return (false, None, Some(msg)),
        };

        // Find the ledger
        let (_, ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Look up the deposit balance
        let id_hex = hex::encode(deposit_id);
        match ledger.state.deposits.get(&deposit_id) {
            Some(deposit) => {
                let block_height = self.wallet.get_block_height().unwrap_or(0);
                let result = serde_json::json!({
                    "deposit_id": id_hex,
                    "balance_msats": deposit.balance,
                    "balance_sats": deposit.balance / 1000,
                    "locked_msats": deposit.locked_balance,
                    "block_height": block_height,
                });
                tracing::debug!("Balance query: {} -> {} msats", id_hex, deposit.balance);
                (true, Some(result.to_string()), None)
            }
            None => (
                false,
                None,
                Some(format!("Deposit not found for id: {}", id_hex)),
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

        let deposit_id = match parse_deposit_id_param(request) {
            Ok(id) => id,
            Err(msg) => return (false, None, Some(msg)),
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

    /// Admin: open a ledger against an existing reserves UTXO.
    pub(crate) async fn process_ledger_open_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        // NB: no wallet sync here. Opening a ledger is a pure declaration —
        // `open_ledger` uses a synthetic genesis and provisions the
        // per-ledger wallet locally, touching no chain backend. A node-wallet
        // sync would only couple this request to esplora availability: on a
        // slow/rate-limited backend it blocks (or hard-fails) a request that
        // needs nothing from the chain. The on-chain commitment happens later
        // at `quorum begin`, which syncs the relevant ledger wallet itself.

        // Optional collateral ratio. Stored on the LedgerOpen so
        // every later rotation (`quorum begin`, recovery rotation)
        // can preserve the operator's chosen split.
        let collateral_bps = request
            .params
            .get("collateral_bps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);

        let ledger = match self.open_ledger(collateral_bps) {
            Ok(l) => l,
            Err(e) => return (false, None, Some(format!("open_ledger: {}", e))),
        };
        let ledger_id = ledger.ledger_id_hex();

        // Persist via the dirty pass, and publish the genesis LedgerOpen now:
        // the dirty pass only writes to disk, and without seq 0 on the relay a
        // member can never find the original operator, so a dispute stalls
        // before confiscation. (broadcast_last_update clones before awaiting,
        // so it is safe from this Send-requiring handler.)
        self.dirty_ledgers.lock().unwrap().insert(ledger_id.clone());
        if let Err(e) = self.broadcast_last_update(&ledger_id).await {
            tracing::warn!(
                "ledger_open: LedgerOpen for {} not published: {}",
                &ledger_id[..16],
                e
            );
        }

        let result = serde_json::json!({
            "ledger_id": ledger_id,
            "reserves_key": ledger.state.reserves_key,
            "operator": ledger.state.operator_key.to_string(),
        });
        (true, Some(result.to_string()), None)
    }

    /// Handle a wallet → quorum-member `delivery_embed` request (DEP-12).
    ///
    /// The wallet pays a quorum member to anchor an unprocessed
    /// request's hash on the member's own ledger via `DeliveryEmbed`
    /// (disc 80). The embed becomes part of the member's ledger
    /// history and gets broadcast as a normal Kind 9100 update; once
    /// the operator co-signs a subsequent member ledger update, the
    /// operator's `member_ledger_hash` causally references the embed,
    /// proving they've seen the request hash.
    ///
    /// Request params (JSON):
    ///   - `request_hash`: 32-byte hex SHA256 of the original signed
    ///     request payload the wallet wants embedded
    ///   - `target_ledger_id`: 32-byte hex of the operator's ledger
    ///     where the request should have been processed
    ///   - `target_operator`: 33-byte hex compressed pubkey of the
    ///     target operator
    ///
    /// `request.ledger_id` (the LedgerRequest's outer field) selects
    /// which of the member's own ledgers receives the embed. The
    /// member can run multiple ledgers; the wallet picks one.
    ///
    /// Pricing/payment is intentionally out of scope here — for now
    /// the embed is unconditional. A future `payment_commitment`
    /// param can gate it (e.g., a TransferLock from the wallet's
    /// deposit on this member's ledger).
    pub(crate) async fn process_delivery_embed_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::messages::LedgerOperation;

        let request_hash_hex = match request.params.get("request_hash").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing request_hash parameter".to_string()),
                )
            }
        };
        let request_hash: [u8; 32] = match hex::decode(request_hash_hex) {
            Ok(b) => match b.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return (
                        false,
                        None,
                        Some("request_hash must be 32 bytes (64 hex chars)".to_string()),
                    )
                }
            },
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Invalid request_hash hex: {}", e)),
                )
            }
        };

        let target_ledger_id_hex = match request
            .params
            .get("target_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing target_ledger_id parameter".to_string()),
                )
            }
        };
        let target_ledger_id: [u8; 32] = match hex::decode(target_ledger_id_hex) {
            Ok(b) => match b.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return (
                        false,
                        None,
                        Some("target_ledger_id must be 32 bytes (64 hex chars)".to_string()),
                    )
                }
            },
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Invalid target_ledger_id hex: {}", e)),
                )
            }
        };

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
        let target_operator = match target_operator_hex.parse::<bitcoin::secp256k1::PublicKey>() {
            Ok(pk) => pk,
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Invalid target_operator pubkey: {}", e)),
                )
            }
        };

        // Resolve which of our ledgers should receive the embed.
        let (ledger_id, _ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => {
                return (
                    false,
                    None,
                    Some("Ledger not found on this member".to_string()),
                )
            }
        };

        let operation = LedgerOperation::DeliveryEmbed {
            request_hash,
            target_ledger_id,
            target_operator,
        };

        match self.commit_operation(&ledger_id, operation).await {
            Ok(event_id) => {
                // Look up the new sequence + tip hash so the wallet
                // can pin causal evidence to a specific point on our
                // chain. commit_operation has already advanced the
                // ledger by the time it returns.
                let (sequence, content_hash) = match self.get_ledger_by_ledger_id(&ledger_id) {
                    Some((_, l)) => (l.state.sequence, hex::encode(l.state.chain_tip_hash)),
                    None => (0, String::new()),
                };
                tracing::info!(
                    "DeliveryEmbed committed: ledger={}... seq={} request_hash={}...",
                    &ledger_id[..16.min(ledger_id.len())],
                    sequence,
                    &request_hash_hex[..16]
                );
                let result = serde_json::json!({
                    "ledger_id": ledger_id,
                    "event_id": event_id,
                    "sequence": sequence,
                    "tip_hash": content_hash,
                    "request_hash": request_hash_hex,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (
                false,
                None,
                Some(format!("Failed to commit DeliveryEmbed: {}", e)),
            ),
        }
    }
}
