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
    // Cosigner side of the round-trip. Tagged with the same `content_hash` the
    // requester's `request_cosign` span carries, so a slow cosign can be traced
    // across the two processes by grepping that hash.
    #[tracing::instrument(
        name = "cosign_sign",
        skip_all,
        fields(content_hash = request.params.get("content_hash_hex").and_then(|v| v.as_str()).unwrap_or(""))
    )]
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
                            self.ensure_actor_for(&request.ledger_id);
                            if let Some(handle) =
                                self.ledger_actors.lock().unwrap().get(&request.ledger_id)
                            {
                                handle.try_send(super::super::ledger_actor::LedgerEvent::Inbound(
                                    Box::new(update),
                                ));
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
                // DEP-05 §"Deposed operator" (an expiry dispute does not freeze).
                if let Some(why) = crate::node::cosign_policy::refusal_for(
                    &ledgers,
                    &request.ledger_id,
                    &ledger,
                    &self.node_id_hex,
                ) {
                    return (
                        false,
                        None,
                        Some(format!(
                            "Ledger {}... deposed: {}",
                            &request.ledger_id[..16.min(request.ledger_id.len())],
                            why
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

        // Parse the v2 cosign_data (DEP-02 §Signing). Everything below reads the
        // signed fields from here, so what we check is exactly what we sign.
        let fields = match deposits_core::types::CosignData::parse(&cosign_data) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("Cosign REFUSED: {}", e);
                return (false, None, Some(e));
            }
        };
        if let Err(msg) = check_cosign_header(
            &fields,
            sequence_number,
            operator_ledger_arc
                .as_ref()
                .map(|arc| arc.read().unwrap().ledger_id()),
            self.wallet.get_block_height().unwrap_or(0),
            |h| self.wallet.block_hash_at(h),
        ) {
            tracing::warn!(
                "Cosign REFUSED for {}... seq {}: {}",
                &request.ledger_id[..16.min(request.ledger_id.len())],
                sequence_number,
                msg
            );
            return (false, None, Some(msg));
        }

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
        // Anti-equivocation gate: a cosigner only ever signs a STRICTLY-ADVANCING
        // sequence (the next one we don't have yet), or — idempotently — the
        // *exact* update it already holds at an already-committed sequence.
        // Putting our signature on a DIFFERENT update at a sequence we've already
        // committed is equivocation, and it's the whole reason a single operator
        // state-rollback cascaded into two separately-2/2-cosigned seq-11080s:
        // the old gate only rejected "ahead of me" and happily re-signed anything
        // at-or-below our tip. Cosigners are kept current by the freshness barrier,
        // so checking the request against our own committed history is sufficient.
        // Set when the request is for the exact update we already committed at
        // that sequence (an idempotent re-sign, e.g. a request that queued behind
        // a stall until the update had landed). It was validated when we applied
        // it; validating it again against the state it produced double-counts it
        // (a TransferLock reads as locking twice), so that step is skipped below.
        let mut already_committed = false;
        if let Some(ref arc) = operator_ledger_arc {
            let ledger = arc.read().unwrap();
            let expected_seq = ledger.next_sequence();
            // For an already-committed sequence, decide idempotent-vs-equivocation
            // from the SIGNED bytes: does cosign_data (every signed field)
            // reconstruct the exact update we hold at that seq? We deliberately do
            // NOT key off the request's content_hash_hex — it's attacker-supplied
            // and decoupled from what actually gets signed, so a requester could
            // pass the genuine committed hash here while signing a different
            // cosign_data. `None` = the seq is below our in-memory window.
            let resign_matches = if sequence_number < expected_seq {
                ledger
                    .history
                    .iter()
                    .rev()
                    .find(|u| u.sequence_number == sequence_number)
                    .map(|u| u.cosign_fields() == fields)
            } else {
                None
            };
            already_committed = resign_matches == Some(true);
            let lid = &request.ledger_id[..16.min(request.ledger_id.len())];
            match cosign_seq_gate(sequence_number, expected_seq, resign_matches) {
                CosignSeqGate::Allow => {}
                CosignSeqGate::Behind => {
                    tracing::info!(
                        "Cosign seq mismatch: expected {}, got {} for {}...",
                        expected_seq,
                        sequence_number,
                        lid
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
                CosignSeqGate::Equivocation => {
                    tracing::warn!(
                        "Cosign REFUSED (equivocation): seq {} already committed to a \
                         different update than requested ({}…) for {}...",
                        sequence_number,
                        hex::encode(&_content_hash[..4]),
                        lid
                    );
                    return (
                        false,
                        None,
                        Some(format!(
                            "Equivocation refused: seq {} already committed to a different update",
                            sequence_number
                        )),
                    );
                }
                CosignSeqGate::OutsideWindow => {
                    tracing::warn!(
                        "Cosign REFUSED: seq {} below tip {} but outside history window \
                         for {}... — cannot verify non-equivocation",
                        sequence_number,
                        expected_seq.saturating_sub(1),
                        lid
                    );
                    return (
                        false,
                        None,
                        Some(format!(
                            "Cannot verify seq {} (below tip, outside window)",
                            sequence_number
                        )),
                    );
                }
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
        // Verify the update chains from our local tip — if it doesn't, we haven't
        // validated the intervening updates and MUST refuse to sign.
        {
            let cosign_prev_hash = fields.previous_hash;

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

            match LedgerOperation::tlv_decode(fields.message) {
                Ok(operation) => {
                    // Validate against local ledger state — unless it is already
                    // part of that state (see `already_committed`).
                    let validate_against = if already_committed {
                        None
                    } else {
                        operator_ledger_arc.as_ref()
                    };
                    if let Some(arc) = validate_against {
                        let ledger = arc.read().unwrap();
                        // Cosigner-edge policy + expiry check. Refuses to
                        // sign anything past `quorum_expiry`, including a
                        // fresh `QuorumBegin`. Operators must rotate before
                        // the deadline; missing it forces them onto the
                        // Tier-1 (operator-alone after expiry) recovery
                        // path. We use the wallet's view of the chain tip
                        // — fresh enough since the wallet syncs every
                        // periodic_interval.
                        let current_block_height = self.wallet.get_block_height().unwrap_or(0);
                        if let Err(e) = ledger.validate_for_cosign(&operation, current_block_height)
                        {
                            tracing::warn!(
                                "Cosign validation FAILED (policy/expiry): seq={} op={} error={}",
                                sequence_number,
                                Self::format_op_short(&operation),
                                e
                            );
                            return (false, None, Some(format!("Cosign refused: {}", e)));
                        }
                        // Cosigner's pre-sign gate. `check_speculative`
                        // is the canonical "would this op be conforming
                        // if I signed it?" check: it runs the state
                        // transition speculatively and the conformance
                        // verifier (reserve sufficiency on Credit/
                        // Complete ops, witness verification on Lock/
                        // Fulfill ops, etc.), folding any state-machine
                        // rejection into a `ConformanceViolation::
                        // StateMachineRejected` so we get a single
                        // unified Vec back. By refusing to sign anything
                        // that surfaces a violation here, we maintain
                        // the invariant that every `SignedLedgerUpdate`
                        // that advances `LedgerState` (via
                        // `apply_signed`) has already been blessed for
                        // conformance.
                        //
                        // `current_block_height` (from
                        // `self.wallet.get_block_height()` above) is
                        // the cosigner's view of the tip; the verifier
                        // uses it for descriptor `after()` checks.
                        let violations = ledger.state.check_speculative(
                            &operation,
                            &deposits_core::dep16::Dep16Authorizer::new(),
                            current_block_height,
                        );
                        if !violations.is_empty() {
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
                        tracing::debug!(
                            "Cosign validation passed: seq={} op={}",
                            sequence_number,
                            Self::format_op_short(&operation)
                        );
                    }

                    // For QuorumBegin, verify the referenced reserves outpoint
                    // exists on-chain, is unspent, has enough confirmations,
                    // and carries the declared value. Without this, a
                    // cosigner attesting the rotation would be rubber-
                    // stamping a UTXO they never checked — exactly the gap
                    // that motivated this check.
                    // DEP-03 §"Rotation ordering": a QuorumBegin that rotates the
                    // current vault is recorded before its rotation is broadcast; the
                    // request carries the signed rotation, which we verify instead.
                    let rotating_history: Option<(
                        Vec<deposits_core::SignedLedgerUpdate>,
                        deposits_core::LedgerState,
                    )> = if matches!(operation, LedgerOperation::QuorumBegin { .. }) {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        ledgers.get(&request.ledger_id).and_then(|arc| {
                            let l = arc.read().unwrap();
                            deposits_core::rotation_order::rotating_quorum_begin_seq(&l.history)
                                .map(|_| (l.history.clone(), l.state.clone()))
                        })
                    } else {
                        None
                    };
                    if let Some((history, pre_state)) = rotating_history {
                        let tx: Option<bitcoin::Transaction> = request
                            .params
                            .get("rotation_tx")
                            .and_then(|v| v.as_str())
                            .and_then(|h| hex::decode(h).ok())
                            .and_then(|b| bitcoin::consensus::deserialize(&b).ok());
                        let Some(tx) = tx else {
                            let msg = "a rotating QuorumBegin must carry rotation_tx".to_string();
                            tracing::warn!("Refusing cosign: {}", msg);
                            return (false, None, Some(msg));
                        };
                        let splice_prevout = match &operation {
                            LedgerOperation::QuorumBegin {
                                splice_in_outpoint: Some((stxid, svout)),
                                ..
                            } => match self.wallet.splice_prevout(*stxid, *svout) {
                                Ok(p) => Some(p),
                                Err(e) => {
                                    tracing::warn!("Refusing cosign: {}", e);
                                    return (false, None, Some(e));
                                }
                            },
                            _ => None,
                        };
                        if let Err(e) = deposits_core::rotation_order::verify_rotation_tx(
                            &history,
                            &pre_state,
                            fields.block_height,
                            &operation,
                            &tx,
                            self.wallet.network(),
                            splice_prevout,
                        ) {
                            tracing::warn!("Refusing cosign: {}", e);
                            return (false, None, Some(e));
                        }
                        self.handler
                            .inflight_rotations
                            .lock()
                            .unwrap()
                            .insert(tx.compute_txid(), tx);
                    } else if let LedgerOperation::QuorumBegin {
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
                        let expected_sats =
                            reserves_amount_msats.saturating_add(*collateral_amount_msats) / 1000;
                        let txid = bitcoin::Txid::from_raw_hash(
                            bitcoin::hashes::sha256d::Hash::from_byte_array(*new_outpoint_txid),
                        );
                        match self
                            .wallet
                            .get_outpoint_value_and_confs(txid, *new_outpoint_vout)
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
        }

        // DEP-02 v2 cosign digest over the exact bytes the operator sent (which
        // parse above has checked are a well-formed cosign_data).
        let hash = deposits_core::types::SignedLedgerUpdate::cosign_digest_for_data(
            &cosign_data,
            &member_ledger_hash,
        );

        // Sign with Schnorr (BIP-340) via the Signer — anti-equivocation
        // policy keys off cosign_update(operator_ledger, seq, member_head).
        let operator_ledger_id_bytes: [u8; 32] = match hex::decode(&request.ledger_id)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => return (false, None, Some("invalid operator ledger_id".to_string())),
        };
        use deposits_signer_api::SignContext;
        let sig_bytes = match self.handler.signer.bip340_sign(
            &SignContext::cosign_update(
                operator_ledger_id_bytes,
                sequence_number,
                member_ledger_hash,
            ),
            &hash,
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
                if let Some(why) = crate::node::cosign_policy::refusal_for(
                    &ledgers,
                    &request.ledger_id,
                    &ledger,
                    &self.node_id_hex,
                ) {
                    tracing::warn!(
                        "Refusing to cosign offer for ledger {} - deposed: {}",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        why
                    );
                    return (
                        false,
                        None,
                        Some(format!(
                            "Ledger operator is deposed ({why}) - cannot co-sign offers"
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

            for arc in ledgers.values() {
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
        let sig_bytes = match self
            .handler
            .signer
            .bip340_sign(&SignContext::no_ledger(SigPurpose::DepositOffer), &msg_hash)
        {
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

/// Outcome of the anti-equivocation sequence gate (see `cosign_seq_gate`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CosignSeqGate {
    /// Sign it: either the next sequence we don't have, or the *identical*
    /// update we already hold at an already-committed sequence (idempotent).
    Allow,
    /// The request is ahead of us — we're missing history; catch up, don't sign.
    Behind,
    /// A *different* update at a sequence we already committed → equivocation.
    Equivocation,
    /// Below our tip but pruned out of our history window — can't prove it isn't
    /// equivocation, so refuse.
    OutsideWindow,
}

/// Maximum distance, in blocks, between an update's `block_height` and the
/// cosigner's own chain height.
pub(crate) const COSIGN_MAX_BLOCK_SKEW: u32 = 6;

/// Header checks a cosigner makes on the v2 `cosign_data` before signing it
/// (DEP-02 §Signing binds `ledger_id`, `block_height` and `block_hash`):
///
/// - `sequence_number` is the one the request names;
/// - `ledger_id` is the ledger we replicate and are answering about;
/// - when our chain height is known (nonzero), `block_height` is within
///   [`COSIGN_MAX_BLOCK_SKEW`] of it;
/// - when `block_hash` is nonzero and we can look up our chain's hash at
///   `block_height`, they agree. If the lookup fails we skip this check.
pub(crate) fn check_cosign_header(
    fields: &deposits_core::types::CosignData<'_>,
    request_sequence: u64,
    replica_ledger_id: Option<[u8; 32]>,
    own_height: u32,
    block_hash_at: impl FnOnce(u32) -> Option<[u8; 32]>,
) -> Result<(), String> {
    if fields.sequence_number != request_sequence {
        return Err(format!(
            "sequence mismatch: request says {}, cosign_data says {}",
            request_sequence, fields.sequence_number
        ));
    }
    match replica_ledger_id {
        Some(id) if id == fields.ledger_id => {}
        _ => return Err("ledger_id mismatch".to_string()),
    }
    if own_height != 0 && fields.block_height.abs_diff(own_height) > COSIGN_MAX_BLOCK_SKEW {
        return Err(format!(
            "block_height {} is more than {} blocks from our height {}",
            fields.block_height, COSIGN_MAX_BLOCK_SKEW, own_height
        ));
    }
    if fields.block_hash != [0u8; 32] {
        if let Some(ours) = block_hash_at(fields.block_height) {
            if ours != fields.block_hash {
                return Err(format!(
                    "block_hash mismatch at height {}",
                    fields.block_height
                ));
            }
        }
    }
    Ok(())
}

/// The cosigner's core safety rule, factored out pure so it's unit-testable.
///
/// A correct cosigner only ever puts its signature on a STRICTLY-ADVANCING
/// sequence (`expected_seq`, the next one it doesn't yet have), or — to tolerate
/// the high-TPS case where a member runs 1-2 seqs ahead of the cosign request —
/// the *exact same* update it already committed at an already-passed sequence.
/// Signing a *different* update at an already-committed sequence is equivocation,
/// which is how one operator state-rollback produced two separately-2/2-cosigned
/// seq-11080s. The old gate only rejected the `Behind` case.
///
/// For the already-committed (`< expected_seq`) case the caller passes
/// `resign_matches_committed`: `Some(true)` iff the *signed bytes* (`cosign_data`'s
/// `previous_hash` + `message`) reconstruct the exact update we hold at that
/// sequence, `Some(false)` if they reconstruct a different one (equivocation),
/// `None` if the sequence is below our in-memory window. This MUST be derived
/// from `cosign_data` (what actually gets signed), never from the request's
/// `content_hash_hex` claim — that field is attacker-supplied and decoupled from
/// the signature, so trusting it would let a requester pass the genuine
/// committed hash through the gate while signing a different update.
pub(crate) fn cosign_seq_gate(
    sequence_number: u64,
    expected_seq: u64,
    resign_matches_committed: Option<bool>,
) -> CosignSeqGate {
    use std::cmp::Ordering::*;
    match sequence_number.cmp(&expected_seq) {
        Greater => CosignSeqGate::Behind,
        Equal => CosignSeqGate::Allow, // the next update we don't have yet
        Less => match resign_matches_committed {
            Some(true) => CosignSeqGate::Allow, // idempotent re-sign of the same bytes
            Some(false) => CosignSeqGate::Equivocation,
            None => CosignSeqGate::OutsideWindow,
        },
    }
}

#[cfg(test)]
mod cosign_seq_gate_tests {
    use super::{cosign_seq_gate, CosignSeqGate};

    #[test]
    fn signs_the_next_sequence() {
        // tip=9 (expected_seq=10), asked to sign 10 → the normal next update.
        assert_eq!(cosign_seq_gate(10, 10, None), CosignSeqGate::Allow);
    }

    #[test]
    fn refuses_when_behind() {
        // asked to sign 12 but we only expect 10 → we're missing history.
        assert_eq!(cosign_seq_gate(12, 10, None), CosignSeqGate::Behind);
    }

    #[test]
    fn idempotent_resign_of_identical_bytes_allowed() {
        // We're ahead (expected 10), re-sign 8, and cosign_data reconstructs the
        // SAME update we committed there → fine (high-TPS retry case).
        assert_eq!(cosign_seq_gate(8, 10, Some(true)), CosignSeqGate::Allow);
    }

    #[test]
    fn different_bytes_at_committed_seq_is_equivocation() {
        // The whole incident: cosign_data reconstructs a DIFFERENT update than
        // what we committed at that seq → refuse. (Pre-fix the gate keyed off the
        // attacker-supplied content_hash and could be tricked into Allow.)
        assert_eq!(
            cosign_seq_gate(8, 10, Some(false)),
            CosignSeqGate::Equivocation
        );
    }

    #[test]
    fn below_tip_but_pruned_is_refused() {
        // Below tip but not in our window → can't verify → refuse.
        assert_eq!(cosign_seq_gate(8, 10, None), CosignSeqGate::OutsideWindow);
    }
}

#[cfg(test)]
mod cosign_header_tests {
    use super::{check_cosign_header, COSIGN_MAX_BLOCK_SKEW};
    use deposits_core::types::CosignData;

    fn fields(block_height: u32, block_hash: [u8; 32]) -> CosignData<'static> {
        CosignData {
            sequence_number: 7,
            ledger_id: [0xaa; 32],
            block_height,
            block_hash,
            previous_hash: [0xcc; 32],
            message: &[0, 1, 42],
        }
    }

    #[test]
    fn accepts_matching_header() {
        let f = fields(850_000, [0xbb; 32]);
        assert_eq!(
            check_cosign_header(&f, 7, Some([0xaa; 32]), 850_002, |_| Some([0xbb; 32])),
            Ok(())
        );
    }

    #[test]
    fn refuses_other_ledger() {
        let f = fields(850_000, [0xbb; 32]);
        assert_eq!(
            check_cosign_header(&f, 7, Some([0xab; 32]), 850_000, |_| None),
            Err("ledger_id mismatch".to_string())
        );
    }

    #[test]
    fn refuses_sequence_other_than_requested() {
        let f = fields(850_000, [0xbb; 32]);
        assert!(check_cosign_header(&f, 8, Some([0xaa; 32]), 850_000, |_| None).is_err());
    }

    #[test]
    fn block_height_skew() {
        let f = fields(850_000, [0u8; 32]);
        let ok = |own| check_cosign_header(&f, 7, Some([0xaa; 32]), own, |_| None);
        assert!(ok(850_000 + COSIGN_MAX_BLOCK_SKEW).is_ok());
        assert!(ok(850_000 - COSIGN_MAX_BLOCK_SKEW).is_ok());
        assert!(ok(850_001 + COSIGN_MAX_BLOCK_SKEW).is_err());
        assert!(ok(849_999 - COSIGN_MAX_BLOCK_SKEW).is_err());
        // Own height unknown: no skew check.
        assert!(ok(0).is_ok());
        // Absent block_height is zero, which is far from any known height.
        let z = fields(0, [0u8; 32]);
        assert!(check_cosign_header(&z, 7, Some([0xaa; 32]), 850_000, |_| None).is_err());
    }

    #[test]
    fn block_hash_checked_when_known() {
        let f = fields(850_000, [0xbb; 32]);
        let run = |ours: Option<[u8; 32]>| {
            check_cosign_header(&f, 7, Some([0xaa; 32]), 850_000, move |h| {
                assert_eq!(h, 850_000);
                ours
            })
        };
        assert!(run(Some([0xbb; 32])).is_ok());
        assert!(run(Some([0xbc; 32])).is_err());
        // Lookup failed: skip the check.
        assert!(run(None).is_ok());
        // Zero block_hash: never looked up.
        let z = fields(850_000, [0u8; 32]);
        assert!(
            check_cosign_header(&z, 7, Some([0xaa; 32]), 850_000, |_| panic!("no lookup")).is_ok()
        );
    }
}
