//! Cosign request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    /// Process a co-sign request from an operator.
    ///
    /// When another operator wants to update their ledger where we are a quorum member,
    pub(crate) fn format_op_short(op: &LedgerOperation) -> String {
        format!("disc:{}", op.discriminant())
    }

    /// they send us a co-sign request. We validate the update and return our ECDSA signature.
    ///
    /// The signature covers: cosign_data || our_ledger_content_hash
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

        // Forward piggybacked updates to the actor before freshness
        // check. The requester includes the previous signed update
        // (seq N-1) so we can catch up inline without waiting for
        // relay delivery. Each update is inserted into the event
        // store and dispatched to the ledger's actor; the actor's
        // `Inbound` handler enforces chain continuity and persists.
        if let Some(prev_arr) = request
            .params
            .get("previous_updates")
            .and_then(|v| v.as_array())
        {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let mut forwarded = 0usize;
            for item in prev_arr {
                if let Some(b64) = item.as_str() {
                    if let Ok(tlv) = BASE64.decode(b64) {
                        if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv) {
                            self.handler.insert_event(&update);
                            if let Some(handle) = self
                                .ledger_actors
                                .lock()
                                .unwrap()
                                .get(&request.ledger_id)
                            {
                                handle.try_send(
                                    super::super::ledger_actor::LedgerEvent::Inbound(Box::new(
                                        update,
                                    )),
                                );
                                forwarded += 1;
                            }
                        }
                    }
                }
            }
            if forwarded > 0 {
                self.catch_up_ledger_from_event_store(&request.ledger_id);
                tracing::debug!(
                    "Forwarded {} piggybacked updates to actor for {}...",
                    forwarded,
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

        let content_hash_hex = match request
            .params
            .get("content_hash_hex")
            .and_then(|v| v.as_str())
        {
            Some(hex) => hex.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing content_hash_hex parameter".to_string()),
                )
            }
        };

        // Decode cosign data
        let cosign_data = match hex::decode(&cosign_data_hex) {
            Ok(data) => data,
            Err(e) => return (false, None, Some(format!("Invalid cosign_data_hex: {}", e))),
        };

        // Decode current hash (used for validation logging)
        let _content_hash: [u8; 32] = match hex::decode(&content_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => {
                return (
                    false,
                    None,
                    Some("content_hash_hex must be 32 bytes".to_string()),
                )
            }
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Invalid content_hash_hex: {}", e)),
                )
            }
        };

        // Find the operator's ledger where we are a quorum member (for sequence validation)
        // Get the target ledger and extract operator/reserves for matching.
        //
        // If we don't have a local replica of the disputed ledger we
        // refuse outright: validate_for_cosign, the chain-continuity
        // check, and the sequence-matches-our-tip check all depend on a
        // replica. Signing blind — as the code used to do whenever the
        // replica was absent — means rubber-stamping whatever sighash
        // arrives.
        let (operator_ledger_arc, target_operator_id, _target_reserves_key) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&request.ledger_id) {
                let ledger = arc.read().unwrap();
                (
                    arc.clone(),
                    ledger.operator_key(),
                    ledger.reserves_key().to_string(),
                )
            } else {
                tracing::warn!(
                    "Cosign REFUSED: no local replica for ledger {} — \
                     can't validate without state",
                    &request.ledger_id[..16.min(request.ledger_id.len())]
                );
                return (
                    false,
                    None,
                    Some(format!(
                        "No local replica for ledger {}; \
                         cosign requires a synced view to validate",
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    )),
                );
            }
        };
        let target_operator_id = Some(target_operator_id);
        let operator_ledger_arc = Some(operator_ledger_arc);

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
                let prev_hash = last_update.content_hash;
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
                        .map(|u| u.content_hash)
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
                        // Cosigner-edge policy + expiry check. Refuses to
                        // sign anything past `quorum_expiry`, including a
                        // fresh `QuorumBegin`. Operators must rotate before
                        // the deadline; missing it forces them onto the
                        // Tier-1 (operator-alone after expiry) recovery
                        // path. We use the wallet's view of the chain tip
                        // — fresh enough since the wallet syncs every
                        // periodic_interval.
                        let current_block_height =
                            self.wallet.get_block_height().unwrap_or(0);
                        if let Err(e) = ledger
                            .validate_for_cosign(&operation, current_block_height)
                        {
                            tracing::warn!(
                                "Cosign validation FAILED (policy/expiry): seq={} op={} error={}",
                                sequence_number,
                                Self::format_op_short(&operation),
                                e
                            );
                            return (
                                false,
                                None,
                                Some(format!("Cosign refused: {}", e)),
                            );
                        }
                        // State-machine apply + conformance check.
                        // `apply_with_verifier` runs the state transition
                        // AND the conformance verifier (reserve
                        // sufficiency on Credit/Complete ops, witness
                        // verification on Lock/Fulfill ops, etc.).
                        // Cosigners that only run bare `state.apply`
                        // accept operations that pass the state machine
                        // but violate ledger invariants — e.g. an
                        // InvoiceCredit that pushes total_deposits past
                        // reserves, or an InvoiceLock whose witness
                        // doesn't satisfy the deposit's descriptor.
                        // That's exactly what cosigning is supposed to
                        // prevent.
                        match ledger.state.apply_with_verifier(
                            &operation,
                            &deposits_core::descriptor::CoreWitnessVerifier,
                        ) {
                            Ok((_, violations)) if !violations.is_empty() => {
                                tracing::warn!(
                                    "Cosign validation FAILED (conformance): seq={} op={} violations={:?}",
                                    sequence_number,
                                    Self::format_op_short(&operation),
                                    violations
                                );
                                return (
                                    false,
                                    None,
                                    Some(format!(
                                        "Cosign refused: conformance violations {:?}",
                                        violations
                                    )),
                                );
                            }
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

                    // For QuorumBegin, verify the referenced reserves outpoint
                    // exists on-chain, is unspent, has enough confirmations,
                    // and carries the declared value. Without this, a
                    // cosigner attesting the rotation would be rubber-
                    // stamping a UTXO they never checked — exactly the gap
                    // that motivated this check.
                    if let LedgerOperation::QuorumBegin {
                        new_outpoint_txid,
                        new_outpoint_vout,
                        amount: reserves_amount_msats,
                        collateral_amount: collateral_amount_msats,
                        ..
                    } = &operation
                    {
                        let required_confs =
                            deposits_core::quorum_policy::default_quorum_begin_confs(
                                self.wallet.network(),
                            );
                        let expected_sats = reserves_amount_msats
                            .saturating_add(*collateral_amount_msats)
                            / 1000;
                        let txid = bitcoin::Txid::from_raw_hash(
                            bitcoin::hashes::sha256d::Hash::from_byte_array(
                                *new_outpoint_txid,
                            ),
                        );
                        match self
                            .wallet
                            .get_outpoint_value_and_confs(txid, *new_outpoint_vout)
                            .await
                        {
                            Ok(Some((value_sats, confs))) => {
                                if value_sats != expected_sats {
                                    let msg = format!(
                                        "QuorumBegin UTXO value mismatch: \
                                         outpoint {}:{} has {} sats, op declares {} sats \
                                         (reserves {} msats + collateral {} msats)",
                                        txid,
                                        new_outpoint_vout,
                                        value_sats,
                                        expected_sats,
                                        reserves_amount_msats,
                                        collateral_amount_msats,
                                    );
                                    tracing::warn!("Refusing cosign: {}", msg);
                                    return (false, None, Some(msg));
                                }
                                if confs < required_confs {
                                    let msg = format!(
                                        "QuorumBegin UTXO under-confirmed: \
                                         outpoint {}:{} has {} confs, need {} on network {:?}",
                                        txid,
                                        new_outpoint_vout,
                                        confs,
                                        required_confs,
                                        self.wallet.network(),
                                    );
                                    tracing::warn!("Refusing cosign: {}", msg);
                                    return (false, None, Some(msg));
                                }
                                tracing::debug!(
                                    "QuorumBegin UTXO verified: {}:{} = {} sats, {} confs",
                                    txid,
                                    new_outpoint_vout,
                                    value_sats,
                                    confs
                                );
                            }
                            Ok(None) => {
                                let msg = format!(
                                    "QuorumBegin UTXO not found or already spent: {}:{}",
                                    txid, new_outpoint_vout
                                );
                                tracing::warn!("Refusing cosign: {}", msg);
                                return (false, None, Some(msg));
                            }
                            Err(e) => {
                                let msg = format!(
                                    "QuorumBegin UTXO lookup failed for {}:{}: {}",
                                    txid, new_outpoint_vout, e
                                );
                                tracing::warn!("Refusing cosign: {}", msg);
                                return (false, None, Some(msg));
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

        // Sign with Schnorr (BIP-340) via the Signer — anti-equivocation
        // policy keys off cosign_update(operator_ledger, seq, member_head).
        let operator_ledger_id_bytes: [u8; 32] = match hex::decode(&request.ledger_id)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => {
                return (
                    false,
                    None,
                    Some("invalid operator ledger_id".to_string()),
                )
            }
        };
        use deposits_signer_api::SignContext;
        let sig_bytes = match self.handler.signer.bip340_sign(
            &SignContext::cosign_update(
                operator_ledger_id_bytes,
                sequence_number,
                member_ledger_hash,
            ),
            hash.as_byte_array(),
        ) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("cosign sign: {}", e))),
        };

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
                            .map(|u| u.content_hash)
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

        // Canonical signing message lives in
        // `deposits_protocol::offer_cosign_signing_message`.
        let msg_hash = deposits_core::signature_utils::offer_cosign_signing_message(
            &request.ledger_id,
            &offer_id,
            &operator_id,
            &funding_address,
            deadline_block,
            &member_ledger_hash,
        );

        // Sign with Schnorr (BIP-340) via the Signer.
        use deposits_signer_api::{SigPurpose, SignContext};
        let sig_bytes = match self.handler.signer.bip340_sign(
            &SignContext::no_ledger(SigPurpose::DepositOffer),
            &msg_hash,
        ) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("offer cosign sign: {}", e))),
        };

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

}
