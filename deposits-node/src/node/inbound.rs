use super::*;

impl Node {
    /// Handle a ledger request from Nostr
    pub(crate) async fn handle_ledger_request(&self, mut request: crate::nostr::LedgerRequest) {
        // Resolve truncated ledger IDs (16-char Nostr tags) to full 64-char IDs
        request.ledger_id = self.resolve_ledger_id(&request.ledger_id);

        // Skip requests that THIS daemon process sent (Nostr broadcasts to all subscribers).
        // We track sent event IDs rather than filtering by pubkey, because CLI commands
        // use the same operator key and we want the daemon to process those.
        let is_own_event = {
            let sent = self.sent_events.lock().unwrap();
            if sent.contains(&request.event_id) {
                true
            } else {
                self.sent_events_prev
                    .lock()
                    .unwrap()
                    .contains(&request.event_id)
            }
        };
        if is_own_event {
            tracing::info!(
                "DROP own_event: action={}, ledger={}...",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())]
            );
            return;
        }

        // Check if this request is for a ledger we own or have joined
        let is_our_ledger = self.has_ledger(&request.ledger_id)
            || self.has_ledger_by_reserves_key(&request.ledger_id);
        let is_cross_ledger_sign = request.action == "custody_transfer_sign"
            || request.action == "confiscation_sign"
            || request.action == "rotation_sign";
        // cosign requests can come from ledgers where we're a quorum member
        // (we may not have the full ledger locally, just a QuorumJoin record)
        let is_cosign_request = request.action == "cosign_update"
            || request.action == "cosign_offer"
            || request.action == "cosign_invoice";
        // Admin actions aren't tied to a ledger (e.g. ledger_open is
        // about spinning one up). Gift-wrap unwrapping already populates
        // gift_wrap_sender, and the handlers enforce via
        // check_admin_authorized — skip the ledger ownership check.
        let is_admin_request = matches!(
            request.action.as_str(),
            "ledger_open"
                | "admin_buffer_open"
                | "admin_buffer_fill"
                | "admin_buffer_drain"
                | "admin_buffer_list"
        );

        // Silently drop operator-only actions if we're not the operator
        // (these are broadcast but only the operator should respond)
        let operator_only_actions = [
            "deposit_open",
            "make_offer",
            "withdraw",
            "offer_status",
            "balance_query",
            "make_invoice",
            "pay_invoice",
            "transfer_lock",
            "transfer_complete",
            "bump",
            "complete_offer",
            "deposit_credit",
            "quorum_add",
            "quorum_remove",
            "quorum_join",
            "quorum_begin",
            // consent_request targets the operator of the *member's*
            // collateral ledger (`#l = member_ledger_id`). Any non-operator
            // who happens to subscribe to that ledger (e.g. via the consent
            // piggyback's add_interested_ledger) would otherwise process it
            // and reply with a malformed `false / no error` response.
            "consent_request",
            "resync",
        ];
        if operator_only_actions.contains(&request.action.as_str())
            && !self.is_operator_of_ledger(&request.ledger_id)
        {
            tracing::info!(
                "DROP not_operator: action={}, ledger={}...",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())]
            );
            return;
        }

        if !is_our_ledger && !is_cross_ledger_sign && !is_cosign_request && !is_admin_request {
            tracing::info!(
                "DROP not_ours: action={}, ledger={}...",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())]
            );
            return;
        }

        // Record request age (now - created_at) for all incoming requests.
        // Cosign requests older than 2 seconds are definitely past all retry
        // windows (3 × 500ms timeout + 200ms sleep = 1.9s max) and can be
        // discarded immediately. The 2s threshold accounts for second-precision
        // timestamps and network latency.
        let request_age_secs = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(request.timestamp) as f64
        };
        metrics::record_request_age(&request.action, request_age_secs);

        if is_cosign_request && request_age_secs >= 2.0 {
            metrics::record_cosign_stale_discarded();
            tracing::info!(
                "DROP stale_cosign: action={}, ledger={}..., age={:.0}s",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())],
                request_age_secs,
            );
            return;
        }

        // Discard stale transfer requests. The simulator retries on timeout,
        // so processing old requests wastes cycles and creates state conflicts.
        // 15s is well within the client's 30s lock_timeout.
        let is_transfer =
            request.action == "transfer_lock" || request.action == "transfer_complete";
        if is_transfer && request_age_secs >= 15.0 {
            tracing::debug!(
                "Discarding stale {} request: age={:.0}s, event={}...",
                request.action,
                request_age_secs,
                &request.event_id[..16.min(request.event_id.len())]
            );
            return;
        }

        // For cosign requests: drain any buffered ledger updates and
        // forward them to the relevant ledger's actor BEFORE checking
        // freshness. Updates arrive through the same Nostr
        // subscription but are queued in a separate channel; they
        // may already be buffered but not yet processed because the
        // run loop drains requests before updates. Forwarding here
        // closes the race where a cosign request arrives microseconds
        // before its prerequisite updates are processed.
        if is_cosign_request {
            let mut drained = 0usize;
            // Cap the drain to prevent unbounded sync work — this
            // loop has no .await points, so tokio task cancellation
            // (from JoinSet::abort_all) cannot take effect until the
            // loop exits.
            const MAX_PRE_COSIGN_DRAIN: usize = 50;
            while drained < MAX_PRE_COSIGN_DRAIN {
                let update = match self.nostr.try_recv_ledger_update() {
                    Some(u) => u,
                    None => break,
                };
                self.handler.insert_event(&update.update);
                self.ensure_actor_for(&update.ledger_id);
                if let Some(handle) =
                    self.ledger_actors.lock().unwrap().get(&update.ledger_id)
                {
                    handle.try_send(super::ledger_actor::LedgerEvent::Inbound(Box::new(
                        update.update,
                    )));
                }
                drained += 1;
            }
            if drained > 0 {
                self.catch_up_ledger_from_event_store(&request.ledger_id);
                tracing::debug!("Pre-cosign drain: forwarded {} buffered updates", drained,);
            }
            metrics::record_pre_cosign_drain(drained, true);
        }

        tracing::debug!(
            "Ledger request: action={}, ledger={}..., event={}..., age={:.1}ms",
            request.action,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            &request.event_id[..16.min(request.event_id.len())],
            request_age_secs * 1000.0,
        );

        // Record request received metric
        crate::metrics::record_request_received(&request.action);

        // Start timing request processing
        let start_time = std::time::Instant::now();

        // Process the request based on action
        let (success, result, error) = match request.action.as_str() {
            "deposit_open" => self.process_deposit_open_request(&request).await,
            "make_offer" => self.process_make_offer_request(&request).await,
            "withdraw" => self.process_withdraw_request(&request).await,
            "transfer_lock" => self.process_transfer_lock_request(&request).await,
            "transfer_complete" => self.process_transfer_complete_request(&request).await,
            "custody_transfer_sign" => self.process_custody_transfer_sign_request(&request).await,
            "confiscation_sign" => self.process_confiscation_sign_request(&request).await,
            "rotation_sign" => self.process_rotation_sign_request(&request).await,
            "cooperative_refund_sign" => {
                self.process_cooperative_refund_sign_request(&request).await
            }
            "custodian_query" => self.process_custodian_query_request(&request).await,
            "lottery_reveal" => {
                // When we see another participant's reveal, auto-reveal ours
                self.auto_reveal_preimage(&request.ledger_id).await;
                (true, None, None) // No response needed
            }
            "cosign_update" => {
                // Silently ignore if we're not a quorum member for this ledger
                // (co-sign requests are broadcast, only quorum members should respond)
                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                    tracing::info!(
                        "DROP not_quorum_member: action=cosign_update, ledger={}...",
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    );
                    return;
                }

                let result = self.process_cosign_request(&request).await;
                if !result.0 {
                    tracing::info!(
                        "DROP cosign_failed: action=cosign_update, ledger={}..., error={}",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        result.2.as_deref().unwrap_or("(silent)")
                    );
                    return;
                }
                result
            }
            "cosign_offer" | "cosign_invoice" => {
                // Silently ignore if we're not a quorum member for this ledger
                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                    tracing::info!(
                        "DROP not_quorum_member: action={}, ledger={}...",
                        request.action,
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    );
                    return;
                }

                let result = if request.action == "cosign_offer" {
                    self.process_cosign_offer_request(&request).await
                } else {
                    self.process_cosign_invoice_request(&request).await
                };
                if !result.0 {
                    tracing::info!(
                        "DROP cosign_failed: action={}, ledger={}..., error={}",
                        request.action,
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        result.2.as_deref().unwrap_or("(silent)")
                    );
                    return;
                }
                result
            }
            "offer_status" => self.process_offer_status_request(&request).await,
            "balance_query" => self.process_balance_query_request(&request).await,
            "delivery_embed" => self.process_delivery_embed_request(&request).await,
            "make_invoice" => self.process_make_invoice_request(&request).await,
            "pay_invoice" => self.process_pay_invoice_request(&request).await,
            "ledger_open" => self.process_ledger_open_request(&request).await,
            "admin_buffer_open" => self.process_admin_buffer_open_request(&request).await,
            "admin_buffer_fill" => self.process_admin_buffer_fill_request(&request).await,
            "admin_buffer_drain" => self.process_admin_buffer_drain_request(&request).await,
            "admin_buffer_list" => self.process_admin_buffer_list_request(&request).await,
            "bump" => {
                tracing::info!("Bump requested - syncing wallet and checking deposits...");
                if let Err(e) = self.sync_wallet() {
                    (false, None, Some(format!("Wallet sync failed: {}", e)))
                } else {
                    self.auto_complete_deposits().await;
                    (
                        true,
                        Some(
                            serde_json::json!({"message": "Wallet synced and deposits checked"})
                                .to_string(),
                        ),
                        None,
                    )
                }
            }
            "complete_offer" => self.process_complete_offer_request(&request).await,
            "deposit_credit" => self.process_deposit_credit_request(&request).await,
            "quorum_add" => self.process_quorum_add_request(&request).await,
            "quorum_remove" => self.process_quorum_remove_request(&request).await,
            "quorum_join" => self.process_quorum_join_request(&request).await,
            "consent_request" => self.process_consent_request(&request).await,
            "quorum_begin" => self.process_quorum_begin_request(&request).await,
            "resync" => self.process_resync_request(&request).await,
            "health_status" => self.process_health_status_request().await,
            "health_ping" => self.process_health_ping_request(&request).await,
            _ => {
                tracing::warn!("Unknown request action: {}", request.action);
                (
                    false,
                    None,
                    Some(format!("Unknown action: {}", request.action)),
                )
            }
        };

        // Record request processing time
        let processing_time = start_time.elapsed();
        if !success || processing_time.as_millis() > 10 {
            tracing::info!(
                "[PROFILE] handle_ledger_request action={} took {:.1}ms, age={:.1}ms (success={})",
                request.action,
                processing_time.as_secs_f64() * 1000.0,
                request_age_secs * 1000.0,
                success
            );
        }
        crate::metrics::record_request_processing(
            &request.action,
            &request.ledger_id,
            success,
            processing_time,
        );
        crate::metrics::record_response_sent_for_ledger(
            &request.action,
            &request.ledger_id,
            success,
        );
        // Note: record_response_sent is called inside send_ledger_response (nostr.rs)

        // Send response - parse result String as JSON Value
        let result_json = result.and_then(|s| serde_json::from_str(&s).ok());
        if let Err(e) = self
            .nostr
            .send_ledger_response(
                &request.event_id,
                &request.ledger_id,
                &request.action,
                success,
                result_json,
                error.clone(),
                request.gift_wrap_sender.as_deref(),
            )
            .await
        {
            tracing::error!("Failed to send response: {}", e);
        } else if success {
            tracing::info!(
                "SEND response: action={}, ledger={}..., success=true, {:.0}ms",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())],
                processing_time.as_secs_f64() * 1000.0
            );
        } else {
            tracing::info!(
                "SEND response: action={}, ledger={}..., success=false, error={}",
                request.action,
                &request.ledger_id[..16.min(request.ledger_id.len())],
                error.unwrap_or_default()
            );
        }
    }

    /// Handle an incoming ledger update - validate and auto-dispute if invalid
    #[tracing::instrument(
        name = "handle_ledger_update",
        skip(self, inbound),
        fields(
            ledger = &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
            seq = inbound.update.sequence_number,
            content = hex::encode(&inbound.update.content_hash[..8]),
        ),
    )]
    pub(crate) async fn handle_ledger_update(&self, inbound: crate::nostr::InboundLedgerUpdate) {
        // Check if we care about this ledger (we're a quorum member)
        if !self.is_quorum_member_of_ledger(&inbound.ledger_id) {
            return; // Not our concern
        }

        // Index in event store (content-addressed, handles dedup + validation)
        let is_new = self.handler.insert_event(&inbound.update);
        // Record the Nostr `created_at` we observed so any future
        // resync re-broadcasts pin to the same timestamp and the
        // relay can dedupe by event id. Idempotent at the event-store
        // level — the first recorded value wins, so a same-content
        // echo can't overwrite the outbound path's bookkeeping.
        self.handler
            .event_store
            .lock()
            .unwrap()
            .record_created_at(&inbound.update.content_hash, inbound.timestamp);
        if is_new {
            // Check validity after insert
            let validity_str = {
                let store = self.handler.event_store.lock().unwrap();
                match store.get(&inbound.update.content_hash) {
                    Some(stored) => match stored.validity {
                        deposits_core::event_store::Validity::Valid => "valid",
                        deposits_core::event_store::Validity::Invalid => "invalid",
                        deposits_core::event_store::Validity::Unknown => "unknown",
                    },
                    None => "missing",
                }
            };
            metrics::record_event_store_insert(validity_str);
            metrics::record_ledger_update_received(validity_str);
            tracing::trace!(
                "Event store: indexed seq {} on ledger {}... ({})",
                inbound.update.sequence_number,
                &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                validity_str,
            );
        } else {
            metrics::record_ledger_update_received("duplicate");
        }

        // Find the ledger by ledger_id
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(&inbound.ledger_id).cloned()
        };

        let Some(ledger_arc) = ledger_arc else {
            return; // Ledger not found locally
        };

        // Forward the inbound update to the ledger's actor for chain-
        // continuity check + apply + persist. The actor's `Inbound`
        // handler is the authoritative read path — `handler.ledgers`
        // (which the rest of the daemon still queries synchronously)
        // sees the actor's writes through the shared `Arc<RwLock<Ledger>>`.
        self.ensure_actor_for(&inbound.ledger_id);
        if let Some(handle) = self
            .ledger_actors
            .lock()
            .unwrap()
            .get(&inbound.ledger_id)
        {
            handle.try_send(super::ledger_actor::LedgerEvent::Inbound(Box::new(
                inbound.update.clone(),
            )));
        }

        // Previously: skip if it's our own ledger ("stale in-memory state
        // causes the daemon to dispute itself"). Auditing the post-skip
        // flow shows the worry is already covered by other guards:
        //   - validate_incoming_update_hash_chain returns Ok for any
        //     update with seq < next_seq, so echoes of our own commits
        //     pass validation.
        //   - The apply branch only fires when seq == next_seq AND
        //     prev_hash == tip_hash; echoes (seq < next_seq) are skipped.
        //   - The auto-arm branch has its own `is_operator_of_ledger`
        //     guard (lines below) preventing self-dispute even if
        //     validation fails.
        // Dropping the skip lets the daemon ingest its own broadcasts
        // back from the relay as a normal idempotent path — eliminates
        // the `append_update_to_local_jsonl` workaround that the
        // dangerous-testing CLIs needed to keep their disk in sync.

        // Decide what kind of sender this update came from. Three categories:
        //   1. Current operator — legitimate chain extension. Validate; if it
        //      doesn't extend our chain, that's evidence of operator fraud
        //      (members react), or our own local view is stale (we resync).
        //   2. Active quorum member publishing DisputeEnter — a fork branch
        //      start. Don't apply to main; the dispute lives on the fork and
        //      resolves via the lottery, not by mirroring on this chain.
        //   3. Anyone else — random junk. Anyone can sign anything and tag
        //      it with a ledger_id; that doesn't make it our problem.
        //
        // After DisputeAcquire, the operator key changes. If we see a
        // non-operator update on a disputed ledger, re-import via Nostr to
        // pick up the custody transfer before discarding.
        let sender_role = {
            let ledger = ledger_arc.read().unwrap();
            let is_from_operator =
                inbound.update.operator_id == ledger.state.parent_pubkey;
            let is_from_active_member = ledger
                .state
                .quorum_members
                .iter()
                .any(|m| m.pubkey == inbound.update.operator_id);
            let is_dispute_enter = {
                use deposits_core::tlv::TlvDecode;
                deposits_core::messages::LedgerOperation::tlv_decode(&inbound.update.message)
                    .map(|op| {
                        matches!(
                            op,
                            deposits_core::messages::LedgerOperation::DisputeEnter { .. }
                        )
                    })
                    .unwrap_or(false)
            };
            let in_dispute =
                ledger.state.dispute_state != deposits_core::types::DisputeState::Normal;
            (
                is_from_operator,
                is_from_active_member,
                is_dispute_enter,
                in_dispute,
            )
        };

        let (is_from_operator, is_from_active_member, is_dispute_enter, in_dispute) =
            sender_role;

        if !is_from_operator {
            if is_from_active_member && is_dispute_enter {
                // Member starting a fork branch. Don't apply to the
                // main chain. But — if the DisputeEnter carries
                // QuorumExpired anchor evidence and we're a quorum
                // member of this ledger, verify the evidence and
                // (if valid) auto-arm on our own fork.
                use deposits_core::tlv::TlvDecode;
                if let Ok(deposits_core::messages::LedgerOperation::DisputeEnter {
                    last_valid_sequence,
                    anchor_block_hash: Some(anchor_hash),
                    anchor_block_height: Some(anchor_height),
                    ..
                }) = deposits_core::messages::LedgerOperation::tlv_decode(
                    &inbound.update.message,
                ) {
                    self.handle_fork_dispute_enter(
                        &inbound.ledger_id,
                        last_valid_sequence,
                        anchor_hash,
                        anchor_height,
                        inbound.update.operator_id,
                    )
                    .await;
                } else {
                    tracing::info!(
                        "Fork DisputeEnter (no anchor evidence) on ledger {}... from {}... — not applying",
                        &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                        hex::encode(&inbound.update.operator_id.serialize()[..8]),
                    );
                }
                return;
            }

            if in_dispute {
                // Custody may have transferred via DisputeAcquire. Re-import
                // to pick up the new operator key, then re-check.
                tracing::info!(
                    "Non-operator update on disputed ledger {}... — re-importing to check for custody transfer",
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                );
                let _ = self.reimport_joined_ledger(&inbound.ledger_id).await;

                let ledgers = self.handler.ledgers.lock().unwrap();
                let Some(fresh_arc) = ledgers.get(&inbound.ledger_id) else {
                    return;
                };
                let fresh_ledger = fresh_arc.read().unwrap();
                let now_from_operator =
                    inbound.update.operator_id == fresh_ledger.state.parent_pubkey;
                drop(fresh_ledger);
                drop(ledgers);
                if !now_from_operator {
                    tracing::debug!(
                        "Still non-operator after reimport — dropping update seq {} on ledger {}...",
                        inbound.update.sequence_number,
                        &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    );
                    return;
                }
                // Operator changed — fall through.
            } else {
                tracing::debug!(
                    "Dropping update seq {} on ledger {}... from non-operator non-member {}...",
                    inbound.update.sequence_number,
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    hex::encode(&inbound.update.operator_id.serialize()[..8]),
                );
                return;
            }
        }

        // If the incoming update is ahead of our local copy, try to catch up
        // from the event store first (pure in-memory, no relay I/O).  Only mark
        // as stale for background gap-fill if event store can't bridge the gap.
        {
            let ledger = ledger_arc.read().unwrap();
            let local_seq = ledger.next_sequence();
            if inbound.update.sequence_number > local_seq {
                tracing::info!(
                    "Ledger {}... has gap: local={}, incoming seq={}. Attempting event store catch-up.",
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    local_seq,
                    inbound.update.sequence_number,
                );
                drop(ledger); // release read lock before catch-up

                // Try to catch up from event store (no relay I/O)
                let caught_up = self.catch_up_ledger_from_event_store(&inbound.ledger_id);

                // Re-check if still behind after catch-up
                let still_behind = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    ledgers
                        .get(&inbound.ledger_id)
                        .map(|arc| {
                            let l = arc.read().unwrap();
                            l.next_sequence() < inbound.update.sequence_number
                        })
                        .unwrap_or(true)
                };

                if still_behind {
                    // Mark as stale for background gap-fill (non-blocking)
                    self.stale_joined_ledgers
                        .lock()
                        .unwrap()
                        .insert(inbound.ledger_id.clone());
                    let stale_count = self.stale_joined_ledgers.lock().unwrap().len();
                    metrics::set_stale_joined_ledgers(stale_count);
                    if caught_up > 0 {
                        tracing::info!(
                            "Event store catch-up added {} events but still behind — queued for background fill",
                            caught_up,
                        );
                    } else {
                        tracing::debug!(
                            "Event store has no bridging events — queued for background fill",
                        );
                    }
                } else if caught_up > 0 {
                    tracing::info!(
                        "Event store catch-up bridged the gap (+{} events)",
                        caught_up,
                    );
                }
            }
        }

        // Validate the update (hash chain only — signature format is not yet
        // standardised across the codebase, so signature failures are dropped
        // rather than treated as disputes)
        let validation_result = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let Some(ledger_arc) = ledgers.get(&inbound.ledger_id).cloned() else {
                return;
            };
            drop(ledgers);

            let ledger = ledger_arc.read().unwrap();

            // Skip if already in dispute state
            if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                return;
            }

            ledger.validate_incoming_update_hash_chain(&inbound.update)
        };

        if let Err(e) = validation_result {
            tracing::warn!(
                "!!! INVALID UPDATE DETECTED on ledger {}...: {:?}",
                &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                e
            );
            tracing::warn!(
                "  From operator: {}...",
                hex::encode(inbound.update.operator_id.serialize())[..16].to_string()
            );
            tracing::warn!("  Sequence: {}", inbound.update.sequence_number);

            // The operator must not auto-arm its OWN ledger. Members fork
            // when they detect invalid history; the operator only initiates
            // recovery from the legitimate side. If the operator forks
            // itself in response to a member's fork update (which validates
            // as "invalid" against the operator's main chain), we end up
            // with a self-fork whose reconstructed Taproot voter set
            // disagrees with the on-chain UTXO — every confiscation attempt
            // then fails with "Witness program hash mismatch".
            if self.is_operator_of_ledger(&inbound.ledger_id) {
                tracing::debug!(
                    "Operator does not auto-arm own ledger — fork updates are normal during dispute"
                );
                return;
            }

            // Get the last valid sequence number (the one before this invalid update)
            let last_valid_seq = if inbound.update.sequence_number > 0 {
                inbound.update.sequence_number - 1
            } else {
                0
            };

            // Auto-arm for the dispute
            tracing::info!("Auto-arming for dispute...");
            match self
                .auto_arm_for_dispute(&inbound.ledger_id, last_valid_seq)
                .await
            {
                Ok(()) => {
                    tracing::info!("Successfully auto-armed for dispute on invalid update");
                }
                Err(e) => {
                    tracing::error!("Failed to auto-arm for dispute: {}", e);
                }
            }
        }
        // Validated update apply + persist happens in the LedgerActor
        // (forwarded via `try_send(LedgerEvent::Inbound)` earlier in
        // this function). The previous duplicate apply here raced
        // against the actor on the write lock; consolidating to the
        // actor keeps the apply path single-writer.
    }

    /// Handle a fork-branch `DisputeEnter` carrying QuorumExpired
    /// anchor evidence (received via kind:9100). Runs the verifier in
    /// `deposits-core/src/operation_validation.rs` against our own
    /// block oracle + ledger state; only auto-arms if all three checks
    /// pass (oracle confirms hash at asserted height, height exceeds
    /// our recorded `quorum_expiry`, fork point equals our main-chain
    /// tip).
    ///
    /// Refusal logs the structured reason. The peer's DisputeEnter
    /// still exists on the relay — they just won't have our arm
    /// participating, which (alongside other honest members' refusals)
    /// means their fork can't reach majority for confiscation.
    pub(crate) async fn handle_fork_dispute_enter(
        &self,
        ledger_id: &str,
        last_valid_sequence: u64,
        anchor_block_hash: [u8; 32],
        anchor_block_height: u32,
        disputer_pubkey: bitcoin::secp256k1::PublicKey,
    ) {
        let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];

        // Snapshot ledger state (operator, quorum_expiry, tip sequence,
        // is-this-our-ledger, are-we-a-member) under the lock. Drop
        // the guard before any await.
        let snapshot = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = match ledgers.get(ledger_id) {
                Some(a) => a.clone(),
                None => {
                    tracing::debug!(
                        "fork DisputeEnter for unknown ledger {}; ignoring",
                        ledger_prefix
                    );
                    return;
                }
            };
            drop(ledgers);
            let l = arc.read().unwrap();
            let we_are_operator = l.operator_key() == self.node_id;
            let we_are_member = l
                .state
                .quorum_members
                .iter()
                .any(|m| m.pubkey == self.node_id);
            let quorum_expiry = l.state.quorum_expiry;
            let tip_seq = l.state.sequence;
            (we_are_operator, we_are_member, quorum_expiry, tip_seq)
        };
        let (we_are_operator, we_are_member, quorum_expiry, tip_seq) = snapshot;

        // Operator of own ledger doesn't auto-arm (we can't dispute
        // our own ledger). Non-members don't auto-arm (we have no
        // standing).
        if we_are_operator {
            tracing::debug!(
                "fork DisputeEnter on our own ledger {} from {}... — skipping (operator doesn't auto-arm)",
                ledger_prefix,
                hex::encode(&disputer_pubkey.serialize()[..8])
            );
            return;
        }
        if !we_are_member {
            tracing::debug!(
                "fork DisputeEnter on {} from {}... — we're not a quorum member; skipping",
                ledger_prefix,
                hex::encode(&disputer_pubkey.serialize()[..8])
            );
            return;
        }

        let quorum_expiry = match quorum_expiry {
            Some(e) => e,
            None => {
                tracing::warn!(
                    "fork DisputeEnter on {} but ledger has no quorum_expiry; cannot verify",
                    ledger_prefix
                );
                return;
            }
        };

        // Verify the cited anchor evidence. The oracle uses our wallet's
        // esplora client (same one `verify_fraud_broadcast` uses).
        struct WalletOracle<'a> {
            wallet: &'a crate::wallet::Wallet,
        }
        impl<'a> deposits_core::fraud::BlockOracle for WalletOracle<'a> {
            fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
                self.wallet.confirms_block(h)
            }
        }
        let oracle = WalletOracle {
            wallet: &self.wallet,
        };
        if let Err(reason) =
            deposits_core::operation_validation::validate_dispute_enter_quorum_expired(
                &anchor_block_hash,
                anchor_block_height,
                last_valid_sequence,
                quorum_expiry,
                tip_seq,
                &oracle,
            )
        {
            tracing::warn!(
                "Refusing to arm on fork DisputeEnter for {} (from {}...): {}",
                ledger_prefix,
                hex::encode(&disputer_pubkey.serialize()[..8]),
                reason
            );
            return;
        }

        tracing::info!(
            "Fork DisputeEnter for {} verified (anchor height {} > quorum_expiry {}, fork at tip seq {}); auto-arming with our own anchor",
            ledger_prefix, anchor_block_height, quorum_expiry, tip_seq,
        );

        // Auto-arm with FRESH anchor evidence from our own block oracle
        // — don't echo the disputer's; commit to what we observe.
        let our_height = self.wallet.get_block_height().unwrap_or(0);
        let our_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        match self
            .auto_arm_for_dispute_with_anchor(
                ledger_id,
                last_valid_sequence,
                Some((our_hash, our_height)),
            )
            .await
        {
            Ok(()) => tracing::info!("Armed on verified fork DisputeEnter for {}", ledger_prefix),
            Err(e) => tracing::warn!(
                "Failed to auto-arm after verifying fork DisputeEnter for {}: {}",
                ledger_prefix,
                e
            ),
        }
    }

    /// Handle a dispute notification from Nostr
    #[tracing::instrument(name = "handle_dispute", skip(self, dispute), fields(ledger = &dispute.ledger_id[..16.min(dispute.ledger_id.len())]))]
    pub(crate) async fn handle_dispute(&self, dispute: crate::nostr::LedgerDispute) {
        tracing::warn!(
            "!!! DISPUTE RECEIVED for ledger {}...: {} (by {}...)",
            &dispute.ledger_id[..16.min(dispute.ledger_id.len())],
            dispute.reason,
            &dispute.disputer_pubkey[..16.min(dispute.disputer_pubkey.len())]
        );

        tracing::warn!("  Last valid seq: {}", dispute.last_valid_sequence);
        if let Some(vs) = dispute.violation_sequence {
            tracing::warn!("  Violation seq: {}", vs);
        }

        // Check if we're a quorum member of this ledger
        let is_member = self.is_quorum_member_of_ledger(&dispute.ledger_id);
        if !is_member {
            tracing::info!("Not a quorum member of this ledger, skipping auto-arm");
            return;
        }

        tracing::info!("We are a quorum member - auto-participating in dispute");

        // Auto-arm for the dispute
        match self
            .auto_arm_for_dispute(&dispute.ledger_id, dispute.last_valid_sequence)
            .await
        {
            Ok(()) => {
                tracing::info!("Successfully auto-armed for dispute");
            }
            Err(e) => {
                tracing::error!("Failed to auto-arm for dispute: {}", e);
                tracing::warn!(
                    "Manual intervention required: Run 'recovery arm {}'",
                    dispute.ledger_id
                );
            }
        }
    }

    /// Handle an incoming fraud proof broadcast.
    ///
    /// Verifies the proof hash against the embedding, then checks if we're
    /// a quorum member. If so, initiates a custody dispute.
    #[tracing::instrument(name = "handle_fraud_proof", skip(self, fp), fields(ledger = &fp.broadcast.proof.ledger_id[..16.min(fp.broadcast.proof.ledger_id.len())]))]
    pub(crate) async fn handle_fraud_proof(&self, fp: crate::nostr::FraudProofEvent) {
        let broadcast = &fp.broadcast;
        let ledger_id = &broadcast.proof.ledger_id;

        tracing::warn!(
            "Processing fraud proof: {:?} against {} on ledger {}...",
            broadcast.proof.proof_type,
            &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
            &ledger_id[..16.min(ledger_id.len())]
        );

        // 0. Gap-fill any referenced ledgers we don't already have.
        //    `verify_fraud_broadcast` queries the LedgerProvider for the
        //    embedding ledger AND every causal-chain link's ledger.
        //    Missing → reject. Cosigners only hold replicas of ledgers
        //    they joined, so e.g. a `StaleCosignature` whose causal
        //    chain references a peer member's collateral ledger will
        //    fail to verify on every cosigner who isn't a member of
        //    THAT ledger — i.e. almost every cosigner — even though
        //    the broadcast itself is well-formed and the relay has
        //    every link's history. Pre-fetch from the durable relay
        //    before verifying so the verifier sees a complete view.
        //
        //    `reimport_joined_ledger` is the standard gap-fill path;
        //    it skips ledgers we already own/operate, paginates back
        //    through Nostr to fetch missing updates, and inserts them
        //    into `handler.ledgers` under the plain ledger_id key —
        //    exactly what the LedgerProvider below reads from.
        let mut needed: std::collections::HashSet<String> =
            std::iter::once(broadcast.embedding.ledger_id.clone()).collect();
        for link in &broadcast.causal_chain {
            needed.insert(link.ledger_id.clone());
        }
        for lid in &needed {
            let have = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers.contains_key(lid)
            };
            if have {
                continue;
            }
            tracing::info!(
                "Fraud-proof gap-fill: fetching missing ledger {}... from relay",
                &lid[..16.min(lid.len())]
            );
            if let Err(e) = self.reimport_joined_ledger(lid).await {
                tracing::warn!(
                    "Fraud-proof gap-fill failed for ledger {}: {} \
                     (verification will likely refuse if this ledger is referenced)",
                    &lid[..16.min(lid.len())],
                    e
                );
            }
        }

        // 1-3. Structural sanity, embedding, causal chain, AND per-type
        // evidence verification — all live in
        // `deposits_protocol::fraud::verify_fraud_broadcast` so unit tests
        // can exercise the full receiver pipeline against in-memory
        // ledger fixtures + a mock block oracle.
        let proof_hash_hex = hex::encode(broadcast.proof.proof_hash());

        struct DaemonLedgers<'a> {
            handler: &'a Arc<crate::handler::DepositsHandler>,
        }
        impl<'a> deposits_core::fraud::LedgerProvider for DaemonLedgers<'a> {
            fn ledger_history(
                &self,
                ledger_id: &str,
            ) -> Option<Vec<deposits_core::types::SignedLedgerUpdate>> {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(ledger_id)
                    .map(|arc| arc.read().unwrap().history.clone())
            }
        }

        // Block oracle resolves arbitrary block hashes against esplora
        // (same client `Wallet::fetch_block_info` uses for tip queries).
        // `Wallet::confirms_block` returns `None` on unknown / not-in-
        // best-chain / network error, so the verifier's "is the block
        // in my chain?" check fails closed.
        struct WalletOracle<'a> {
            wallet: &'a crate::wallet::Wallet,
        }
        impl<'a> deposits_core::fraud::BlockOracle for WalletOracle<'a> {
            fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
                self.wallet.confirms_block(hash)
            }
        }

        let provider = DaemonLedgers {
            handler: &self.handler,
        };
        let oracle = WalletOracle {
            wallet: &self.wallet,
        };
        if let Err(e) = deposits_core::fraud::verify_fraud_broadcast(
            broadcast,
            &provider,
            &oracle,
        ) {
            tracing::warn!(
                "Fraud proof rejected ({}...): {}",
                &proof_hash_hex[..16],
                e
            );
            return;
        }

        // WinnerCollateralDeviation needs an extra step the protocol-layer
        // dispatch couldn't run (no I/O at that layer): fetch the on-chain
        // claim TX + the value the lottery output held, and feed both into
        // `verify_winner_collateral_deviation`. The pure verifier returns
        // Ok(()) iff a deviation is provable. See DEP-03 §"Claim
        // transaction (multi-input)".
        if matches!(
            broadcast.proof.proof_type,
            deposits_core::fraud::FraudProofType::WinnerCollateralDeviation
        ) {
            if let Err(e) = self
                .verify_winner_collateral_deviation_onchain(broadcast, &oracle)
                .await
            {
                tracing::warn!(
                    "WinnerCollateralDeviation rejected ({}...): {}",
                    &proof_hash_hex[..16],
                    e
                );
                return;
            }
        }

        tracing::warn!(
            "Fraud proof VERIFIED: {} at seq {} on {}, evidence type {:?}",
            &proof_hash_hex[..16],
            broadcast.embedding.sequence,
            &broadcast.embedding.ledger_id[..16.min(broadcast.embedding.ledger_id.len())],
            broadcast.proof.proof_type,
        );

        // 4. Check if we're a quorum member of the accused ledger
        if !self.is_quorum_member_of_ledger(ledger_id) {
            tracing::info!(
                "Not a quorum member of accused ledger {}, skipping",
                &ledger_id[..16]
            );
            return;
        }

        // Cross-ledger propagation policy. The whitepaper describes
        // proof-of-non-conformance on one of an operator's ledgers being
        // presentable to the operator's *other* quorums to trigger
        // slashing there too. This propagation is the protocol's
        // mechanism for ensuring multi-ledger operators can't insulate
        // one ledger from misbehaviour on another.
        //
        // The policy is classification-gated:
        //   - Punitive proofs (everything except QuorumExpired): MAY
        //     propagate. Operators today do this manually via
        //     `recovery publish-fraud-broadcast` against the operator's
        //     other ledger IDs. Future automation will dispatch on
        //     `proof_type.is_respectful() == false`.
        //   - Respectful proofs (QuorumExpired): MUST NOT propagate.
        //     The operator's bond on this ledger is preserved (returned
        //     via the bifurcated confiscation tx); the deadline-miss
        //     fault is local to this ledger only and should not affect
        //     the operator's other quorums.
        //
        // No automated propagation runs in this handler today, so the
        // gate is forward-looking. When automation lands, it'll check
        // `proof.proof_type.is_respectful()` here and skip the cascade
        // for the respectful case.

        // 5. Determine last valid sequence from the proof
        let last_valid_seq = match &broadcast.proof.evidence {
            deposits_core::fraud::FraudEvidence::UncreditedOnchain { proof_sequence, .. } => {
                proof_sequence.saturating_sub(1)
            }
            deposits_core::fraud::FraudEvidence::UncreditedLightning { proof_sequence, .. } => {
                proof_sequence.saturating_sub(1)
            }
            deposits_core::fraud::FraudEvidence::NonConforming { sequence, .. } => {
                sequence.saturating_sub(1)
            }
            deposits_core::fraud::FraudEvidence::QuorumExpired { .. } => {
                // QuorumExpired is respectful: the operator's chain is
                // valid up to its current tip — they just stopped
                // rotating before the deadline. All recorded updates
                // remain conforming; the fork point is "right now."
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(ledger_id)
                    .map(|arc| arc.read().unwrap().next_sequence().saturating_sub(1))
                    .unwrap_or(0)
            }
            _ => {
                // For stale cosign and dispute dereliction, use the
                // embedding sequence as a reference point (the fraud
                // happened before this).
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(ledger_id)
                    .map(|arc| arc.read().unwrap().next_sequence().saturating_sub(1))
                    .unwrap_or(0)
            }
        };

        tracing::warn!(
            "INITIATING DISPUTE based on fraud proof: ledger={}, last_valid_seq={}, type={:?}",
            &ledger_id[..16],
            last_valid_seq,
            broadcast.proof.proof_type
        );

        // 6. Auto-arm for dispute
        let reason = format!("fraud_proof:{:?}", broadcast.proof.proof_type);
        match self.auto_arm_for_dispute(ledger_id, last_valid_seq).await {
            Ok(()) => {
                tracing::warn!("Successfully armed for dispute based on fraud proof");

                // Also broadcast a dispute event referencing the fraud proof.
                // Routes the operator-key BIP-340 sig through the Signer
                // so the daemon doesn't need a local keypair.
                if let Err(e) = self
                    .nostr
                    .publish_dispute(
                        ledger_id,
                        &reason,
                        &format!("Fraud proof verified: {}", &fp.event_id[..16]),
                        broadcast.proof.proof_hash(),
                        last_valid_seq,
                        None,
                        &*self.handler.signer,
                    )
                    .await
                {
                    tracing::error!("Failed to broadcast dispute: {:?}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to arm for fraud-proof dispute: {}", e);
            }
        }
    }

    /// Daemon-side wrapper for `verify_winner_collateral_deviation`. The
    /// pure verifier in deposits-protocol can't do I/O — it needs the
    /// already-fetched claim TX and the lottery output's value. This
    /// helper bridges that gap by fetching both via Esplora before
    /// invoking the verifier.
    ///
    /// Returns `Ok(())` only when the on-chain TX provably deviates from
    /// the disputant's declared replacement collateral. Any other outcome
    /// (no deviation, missing tx, etc.) becomes `Err(reason)` so the
    /// caller can reject the fraud proof.
    async fn verify_winner_collateral_deviation_onchain(
        &self,
        broadcast: &deposits_core::fraud::FraudBroadcast,
        oracle: &dyn deposits_core::fraud::BlockOracle,
    ) -> Result<(), String> {
        let claim_txid_str = match &broadcast.proof.evidence {
            deposits_core::fraud::FraudEvidence::WinnerCollateralDeviation {
                claim_txid,
                ..
            } => claim_txid.clone(),
            _ => return Err("evidence type mismatch".into()),
        };
        let claim_txid_bytes_vec = hex::decode(&claim_txid_str)
            .map_err(|e| format!("claim_txid hex: {}", e))?;
        let claim_txid_bytes: [u8; 32] = claim_txid_bytes_vec
            .try_into()
            .map_err(|_| "claim_txid: expected 32 bytes".to_string())?;
        let claim_txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::Hash::from_byte_array(claim_txid_bytes),
        );
        let claim_tx = self
            .wallet
            .get_transaction(claim_txid)
            .await
            .map_err(|e| format!("fetch claim TX: {}", e))?
            .ok_or_else(|| format!("claim TX {} not on-chain", claim_txid))?;
        // Lottery output value: read it off input 0's prevout. The claim
        // TX must have at least one input. By RC4 convention input 0 is
        // the lottery output. We can't use `get_outpoint_value_and_confs`
        // here because it filters out spent outpoints (and this one is
        // necessarily spent — the claim TX is what spent it). Fetch the
        // prevout's TX directly and read `output[vout].value`.
        let lottery_prevout = claim_tx
            .input
            .first()
            .ok_or_else(|| "claim TX has no inputs".to_string())?
            .previous_output;
        let prevout_tx = self
            .wallet
            .get_transaction(lottery_prevout.txid)
            .await
            .map_err(|e| format!("fetch lottery prevout TX: {}", e))?
            .ok_or_else(|| format!("prevout TX {} not on-chain", lottery_prevout.txid))?;
        let lottery_amount_sats = prevout_tx
            .output
            .get(lottery_prevout.vout as usize)
            .ok_or_else(|| format!("prevout vout {} out of range", lottery_prevout.vout))?
            .value
            .to_sat();
        // Run the pure verifier.
        deposits_core::fraud::verify_winner_collateral_deviation(
            &broadcast.proof,
            &claim_tx,
            lottery_amount_sats,
            oracle,
        )
    }

    /// Check if we're a quorum member of a ledger (by ledger_id hash)
    pub(crate) fn is_quorum_member_of_ledger(&self, ledger_id: &str) -> bool {
        let t0 = std::time::Instant::now();
        // Check if we have this ledger and are the operator
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                return true;
            }
        }

        // Also check for dispute forks where we're the parent (dispute opener)
        for (key, arc) in ledgers.iter() {
            if key.starts_with(ledger_id) && key.len() > ledger_id.len() {
                let ledger = arc.read().unwrap();
                if ledger.state.parent_pubkey == self.node_id {
                    return true;
                }
            }
        }
        drop(ledgers);

        // Check our joined ledgers (QuorumJoin records in our ledger history)
        let joined = self.get_joined_ledger_ids();
        for jid in joined {
            if jid == ledger_id {
                let elapsed = t0.elapsed();
                if elapsed.as_millis() > 1 {
                    tracing::info!(
                        "[PROFILE] is_quorum_member_of_ledger (found via history scan): {:?}",
                        elapsed
                    );
                }
                return true;
            }
        }

        let elapsed = t0.elapsed();
        if elapsed.as_millis() > 1 {
            tracing::info!(
                "[PROFILE] is_quorum_member_of_ledger (not found, full scan): {:?}",
                elapsed
            );
        }
        false
    }

    /// Find the tracking key for a ledger, preferring dispute forks over originals.
    ///
    /// When a dispute is active, we want to operate on the fork (compound key),
    /// not the original Partner copy. This scans ledgers by prefix and returns
    /// the fork key if one exists, otherwise the original key.
    pub(crate) fn find_fork_or_original_by_prefix(&self, ledger_prefix: &str) -> Option<String> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let mut original: Option<String> = None;
        let mut fork: Option<String> = None;

        for key in ledgers.keys() {
            if key.starts_with(ledger_prefix) {
                if key.len() > 64 {
                    // Fork key (compound format with seq + operator prefix)
                    fork = Some(key.clone());
                } else {
                    // Original key (plain ledger_id, 64 hex chars)
                    original = Some(key.clone());
                }
            }
        }

        // Prefer fork over original for dispute operations
        fork.or(original)
    }

    /// Create a dispute fork of a ledger at the given divergence point.
    ///
    /// Clones the Partner copy of the disputed ledger, truncates its history
    /// to `last_valid_seq`, rebuilds state by replaying operations, and stores
    /// the fork under a compound tracking key. The original Partner copy stays
    /// untouched for evidence/auditing.
    ///
    /// Returns the compound tracking key for the fork.
    pub(crate) fn create_dispute_fork(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
    ) -> Result<String, Error> {
        use crate::handler::DepositsHandler;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;

        // Operator pubkey straight from the signer — no per-call seed
        // derivation, and no operator_secret field on Wallet anymore.
        let our_pubkey = self.node_id;

        // Check if we already have a fork for this ledger
        if let Some(existing_fork) = self.handler.find_our_fork(ledger_id) {
            tracing::info!(
                "Already have fork for ledger {}: {}",
                &ledger_id[..16],
                &existing_fork[..32.min(existing_fork.len())]
            );
            return Ok(existing_fork);
        }

        // Clone the Partner copy of the disputed ledger
        let original_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| {
                Error::Protocol(format!("Don't have disputed ledger: {}", &ledger_id[..16]))
            })?;
        let original = original_arc.read().unwrap();

        // Truncate history to last_valid_seq
        let truncated_history: Vec<_> = original
            .history
            .iter()
            .filter(|u| u.sequence_number <= last_valid_seq)
            .cloned()
            .collect();

        // Rebuild state from genesis by replaying truncated history.
        // Start with a fresh state based on the original's genesis parameters.
        let mut fork_state = original.state.clone();

        // Reset derived state fields that will be rebuilt by replay
        fork_state.deposits.clear();
        fork_state.quorum_members.clear();
        fork_state.joined_quorums.clear();
        fork_state.pending_transfers.clear();
        fork_state.quorum_at_fork.clear();
        fork_state.dispute_fork_sequence = 0;
        fork_state.dispute_state = deposits_core::types::DisputeState::Normal;
        fork_state.reserves_amount = 0;
        fork_state.sequence = 0;
        fork_state.chain_tip_hash = [0u8; 32];

        // Create a temporary ledger for replay
        let mut fork = Ledger {
            state: fork_state,
            protocol: Default::default(),
            role: deposits_core::ledger::LedgerRole::Operator, // We operate the fork
            history: truncated_history.clone(),
        };

        // Replay all truncated operations to rebuild state
        for update in &truncated_history {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let Err(e) = fork.apply_state_changes(&op) {
                    tracing::warn!(
                        "Fork replay seq {}: failed to apply state change: {}",
                        update.sequence_number,
                        e
                    );
                }
            }
        }

        // Update sequence/hash from last valid update
        if let Some(last) = truncated_history.last() {
            fork.state.sequence = last.sequence_number;
            fork.state.chain_tip_hash = last.chain_hash();
        }

        // Store under compound key
        let fork_key = DepositsHandler::fork_tracking_key(ledger_id, last_valid_seq, &our_pubkey);

        tracing::info!(
            "Created dispute fork: {} (diverged at seq {}, {} updates)",
            &fork_key[..32.min(fork_key.len())],
            last_valid_seq,
            fork.history.len(),
        );

        self.handler
            .ledgers
            .lock()
            .unwrap()
            .insert(fork_key.clone(), Arc::new(RwLock::new(fork)));

        Ok(fork_key)
    }
}
