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

        // Requests carrying a `#p` addressee target a specific agent —
        // bridges and couriers ride the same Kind 20101 + `#l` pipeline
        // (DEP-04 §"Bridge request envelopes"), so we see their requests
        // on ledgers we subscribe to. If it isn't us, stay silent: the
        // addressee responds, and an eager "Unknown action" error from a
        // bystander would race (and beat) the real reply.
        if let Some(addressee) = &request.addressee {
            if !self.nostr.is_self_addressed(addressee) {
                tracing::debug!(
                    "DROP not_addressee: action={}, p={}...",
                    request.action,
                    &addressee[..16.min(addressee.len())]
                );
                return;
            }
        }

        // Check if this request is for a ledger we own or have joined
        let is_our_ledger = self.has_ledger(&request.ledger_id)
            || self.has_ledger_by_reserves_key(&request.ledger_id);
        let is_cross_ledger_sign = request.action == "custody_transfer_sign"
            || request.action == "confiscation_sign"
            || request.action == "forfeit_sweep_sign"
            || request.action == "lottery_recovery_sign"
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
                | "admin_status"
                | "ledger_drop"
                | "advertise_status"
                | "advertise_set"
                | "advertise_retract"
                | "advertise_refresh"
                | "liquidity_list"
                | "liquidity_create"
                | "liquidity_pause"
                | "liquidity_resume"
                | "liquidity_remove"
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
            "quote_invoice",
            "transfer_lock",
            "transfer_complete",
            "bump",
            "complete_offer",
            "deposit_credit",
            "quorum_add",
            "quorum_remove",
            "quorum_join",
            "quorum_begin",
            "quorum_upgrade",
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
                if let Some(handle) = self.ledger_actors.lock().unwrap().get(&update.ledger_id) {
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
            "forfeit_sweep_sign" => self.process_forfeit_sweep_sign_request(&request).await,
            "lottery_recovery_sign" => {
                // Only a disputant (one holding its own fork of the ledger)
                // answers, as cl-deposits does; anyone else stays silent.
                if !self.is_disputant_of(&request.ledger_id) {
                    tracing::info!(
                        "DROP not_disputant: action=lottery_recovery_sign, ledger={}...",
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    );
                    return;
                }
                self.process_lottery_recovery_sign_request(&request).await
            }
            "rotation_sign" => self.process_rotation_sign_request(&request).await,
            "cooperative_refund_sign" => {
                self.process_cooperative_refund_sign_request(&request).await
            }
            "custodian_query" => self.process_custodian_query_request(&request).await,
            "lottery_reveal" => {
                // Keep the preimage: the request is ephemeral, so the relay
                // will not hand it back when the claim task looks for it.
                if let Some(p) = super::lottery_recovery::reveal_request_preimage(&request.params) {
                    let mut seen = self.seen_lottery_reveals.lock().unwrap();
                    let list = seen.entry(request.ledger_id.clone()).or_default();
                    if !list.contains(&p) {
                        list.push(p);
                    }
                }
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

                // Wait-for-data: when inbound dispatch sees a cosign_update
                // before the SignedLedgerUpdate it references (a real race
                // under Nostr's non-ordered delivery), the cosigner would
                // otherwise validate against stale state and refuse with
                // `quorum_member_unstaged` (or similar). Subscribe to the
                // per-ledger actor's `apply_wakeup` Notify and re-check the
                // local seq after each apply, up to a 500ms deadline.
                // Event-driven — wakes the moment a prior Inbound lands,
                // no busy-polling. If the data never arrives the wait
                // expires and `process_cosign_request` produces the
                // canonical stale-state refusal verdict.
                if let Some(req_seq) = request
                    .params
                    .get("sequence_number")
                    .and_then(|v| v.as_u64())
                {
                    let apply_wakeup = {
                        let map = self.ledger_actors.lock().unwrap();
                        map.get(&request.ledger_id)
                            .map(|h| std::sync::Arc::clone(&h.apply_wakeup))
                    };
                    if let Some(wakeup) = apply_wakeup {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_millis(500);
                        loop {
                            let local_next = {
                                let ledgers = self.handler.ledgers.lock().unwrap();
                                ledgers
                                    .get(&request.ledger_id)
                                    .map(|arc| arc.read().unwrap().next_sequence())
                                    .unwrap_or(0)
                            };
                            if local_next >= req_seq {
                                break;
                            }
                            if tokio::time::Instant::now() >= deadline {
                                break;
                            }
                            // Wait for the next state advance OR the deadline.
                            // tokio::select! short-circuits to whichever fires first.
                            tokio::select! {
                                _ = wakeup.notified() => {}
                                _ = tokio::time::sleep_until(deadline) => break,
                            }
                        }
                    }
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
            "delivery_embed" => {
                // delivery_embed extends the member's own ledger — only
                // the ledger's operator can sign that extension. The
                // wallet broadcasts the request, and every daemon that
                // subscribes to the ledger's kind picks it up; the
                // non-operator daemons would otherwise commit-and-fail
                // with `bad_operator_signature` (they sign with their
                // own key but the update's operator_id is fixed at the
                // ledger's original operator). The wallet sees
                // whichever response arrives first, so a cosigner's
                // doomed failure typically wins over the operator's
                // success. Drop silently here so only the actual
                // operator responds. Mirrors the "DROP cosign_failed"
                // pattern just above.
                let is_operator = self
                    .handler
                    .ledgers
                    .lock()
                    .unwrap()
                    .get(&request.ledger_id)
                    .map(|arc| arc.read().unwrap().state.operator_key == self.node_id)
                    .unwrap_or(false);
                if !is_operator {
                    tracing::info!(
                        "DROP delivery_embed: not operator of ledger {}... — \
                         the actual operator will respond",
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    );
                    return;
                }
                self.process_delivery_embed_request(&request).await
            }
            "make_invoice" => self.process_make_invoice_request(&request).await,
            "pay_invoice" => self.process_pay_invoice_request(&request).await,
            "quote_invoice" => self.process_quote_invoice_request(&request).await,
            "ledger_open" => self.process_ledger_open_request(&request).await,
            "admin_buffer_open" => self.process_admin_buffer_open_request(&request).await,
            "admin_buffer_fill" => self.process_admin_buffer_fill_request(&request).await,
            "admin_buffer_drain" => self.process_admin_buffer_drain_request(&request).await,
            "admin_buffer_list" => self.process_admin_buffer_list_request(&request).await,
            "admin_status" => self.process_admin_status_request(&request).await,
            "admin_resync_owned" => self.process_admin_resync_owned_request(&request).await,
            "ledger_drop" => self.process_ledger_drop_request(&request).await,
            "advertise_status" => self.process_advertise_status_request(&request).await,
            "advertise_set" => self.process_advertise_set_request(&request).await,
            "advertise_retract" => self.process_advertise_retract_request(&request).await,
            "advertise_refresh" => self.process_advertise_refresh_request(&request).await,
            "liquidity_list" => self.process_liquidity_list_request(&request).await,
            "liquidity_create" => self.process_liquidity_create_request(&request).await,
            "liquidity_pause" => {
                self.process_liquidity_set_paused_request(&request, true)
                    .await
            }
            "liquidity_resume" => {
                self.process_liquidity_set_paused_request(&request, false)
                    .await
            }
            "liquidity_remove" => self.process_liquidity_remove_request(&request).await,
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
            "quorum_upgrade" => self.process_quorum_upgrade_request(&request).await,
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

    /// Drive the confiscation lifecycle for a detected equivocation by arming a
    /// dispute on the accused ledger — the same fork-branch `DisputeEnter` +
    /// auto-arm path the expiry case uses (`auto_arm_for_dispute_with_anchor`).
    /// The evidence is self-contained and already on the relay (the operator's
    /// two conflicting `(seq, content)` updates), so cosigners ground the
    /// confiscation via `fetch_equivocation_inline_evidence` — no kind:9101
    /// embedding/causal-chain needed (a cosigner can't embed on a ledger it
    /// doesn't operate). `last_valid_sequence = equiv_seq − 1`: everything
    /// strictly before the equivocated seq stays canonical and replays onto the
    /// fork. No grace period — equivocation is provable misbehavior, unlike a
    /// deadline miss where the operator gets a self-rescue window.
    pub(crate) async fn emit_equivocation_proof(
        &self,
        update_a: deposits_core::types::SignedLedgerUpdate,
        _update_b: deposits_core::types::SignedLedgerUpdate,
    ) {
        let accused_ledger = update_a.ledger_id_hex();
        let equiv_seq = update_a.sequence_number;
        let last_valid = equiv_seq.saturating_sub(1);

        match self
            .auto_arm_for_dispute_with_anchor(&accused_ledger, last_valid, None)
            .await
        {
            Ok(()) => tracing::warn!(
                "Equivocation on {}... seq {}: armed dispute fork (last_valid={}) — confiscation cascade should follow",
                &accused_ledger[..16.min(accused_ledger.len())],
                equiv_seq,
                last_valid
            ),
            Err(e) => tracing::error!(
                "Equivocation on {}... seq {}: failed to arm dispute: {}",
                &accused_ledger[..16.min(accused_ledger.len())],
                equiv_seq,
                e
            ),
        }
    }

    /// Ledger ids `operator` operates: its Kind 39100 advertisements (tag
    /// `o`, the `d` tag of each) and the ledgers we hold whose operator
    /// (`parent_pubkey`) it is. De-duplicated.
    pub(crate) async fn ledgers_operated_by(
        &self,
        operator: &bitcoin::secp256k1::PublicKey,
    ) -> Vec<String> {
        let advertised = self
            .nostr
            .fetch_ledger_ids_operated_by(&hex::encode(operator.serialize()))
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Contagion: advertisement query for {}... failed: {}",
                    &hex::encode(&operator.serialize()[..8]),
                    e
                );
                Vec::new()
            });
        let held: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(_, arc)| arc.read().unwrap().state.parent_pubkey == *operator)
                .map(|(id, _)| id.clone())
                .collect()
        };
        merge_ledger_ids(advertised, held)
    }

    /// Contagion (DEP-19 §5–6): everyone who signed the non-conforming
    /// `fault` (its operator and each cosigner), against every other ledger
    /// it operates. One self-evident kind:9101 `NonConformingCosignature` per
    /// (signer, ledger); that ledger's own quorum verifies it against the
    /// fault ledger's history and disputes. The fault ledger is not a
    /// target: its own dispute, armed before the fault, judges it. Without
    /// this a colluding cosigner lost nothing for signing a theft, and the
    /// operator lost only the ledger it cheated (cld1 forged on M and kept
    /// A on the devnet). Mirrors cl-deposits' `broadcast-cosigner-contagion`.
    pub(crate) async fn broadcast_contagion(
        &self,
        fault: &deposits_core::types::SignedLedgerUpdate,
        governing_qb: u64,
    ) {
        let mut targets: std::collections::HashMap<bitcoin::secp256k1::PublicKey, Vec<String>> =
            std::collections::HashMap::new();
        let signers = std::iter::once(fault.operator_id)
            .chain(fault.cosignatures.iter().map(|e| e.cosigner_pubkey));
        for pk in signers {
            if pk == self.node_id || targets.contains_key(&pk) {
                continue;
            }
            let ids = self.ledgers_operated_by(&pk).await;
            targets.insert(pk, ids);
        }
        let proofs = deposits_core::fraud::contagion_proofs(
            fault,
            governing_qb,
            &|pk| targets.get(pk).cloned().unwrap_or_default(),
            Some(&self.node_id),
        );
        let fault_ledger = hex::encode(fault.ledger_id);
        for b in &proofs {
            tracing::warn!(
                "Contagion: {}... signed the fault on {}... seq {}; proof against its ledger {}...",
                &b.proof.accused[..16.min(b.proof.accused.len())],
                &fault_ledger[..16],
                fault.sequence_number,
                &b.proof.ledger_id[..16.min(b.proof.ledger_id.len())],
            );
            if let Err(e) = self.nostr.broadcast_fraud_proof(b).await {
                tracing::error!("Contagion: fraud broadcast failed: {}", e);
            }
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
    pub(crate) async fn handle_ledger_update(
        self: &std::sync::Arc<Self>,
        inbound: crate::nostr::InboundLedgerUpdate,
    ) {
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
        if let Some(handle) = self.ledger_actors.lock().unwrap().get(&inbound.ledger_id) {
            handle.try_send(super::ledger_actor::LedgerEvent::Inbound(Box::new(
                inbound.update.clone(),
            )));
        }

        // ── Equivocation detection ──────────────────────────────────────
        // If the operator signed a DIFFERENT update at a sequence we already
        // hold, that's provable double-signing (both bear the operator's
        // BIP-340 signature). Cheap synchronous check here; the emit (build
        // proof + DEP-12 embed + kind:9101 broadcast, which cosigns on our
        // own ledger) is spawned so it never blocks ingest. We never accuse
        // ourselves — operator-side guards (catch-up + the cosign gate)
        // handle self-correction; this path is for cosigners reporting a
        // faulty operator.
        if inbound.update.operator_id != self.node_id {
            let conflict = {
                let l = ledger_arc.read().unwrap();
                if inbound.update.operator_id == l.state.parent_pubkey {
                    l.history
                        .iter()
                        .rev()
                        .find(|u| updates_equivocate(u, &inbound.update))
                        .cloned()
                        .filter(|_| {
                            inbound_binds_to_ledger(&inbound.update, &l.state.ledger_id, &l.history)
                        })
                } else {
                    None
                }
            };
            if let Some(committed) = conflict {
                tracing::warn!(
                    "EQUIVOCATION detected on {}... seq {}: operator double-signed ({} vs {}) — emitting fraud proof",
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    inbound.update.sequence_number,
                    &hex::encode(committed.content_hash)[..8],
                    &hex::encode(inbound.update.content_hash)[..8],
                );
                let node = std::sync::Arc::clone(self);
                let incoming = inbound.update.clone();
                tokio::spawn(async move {
                    node.emit_equivocation_proof(committed, incoming).await;
                });
            }
        }

        // ── Non-conforming-cosignature detection ────────────────────────
        // A quorum-cosigned update from the operator that FAILS our conformance
        // check means the quorum colluded (or a cosigner is faulty) — honest
        // cosigners refuse non-conforming updates at cosign time, so a cosigned
        // one reaching us is the collusion signal. Arm a dispute; the
        // confiscation grounds via `fetch_non_conforming_cosig_inline_evidence`
        // (self-verifying replay over relay history). Only meaningful at the next
        // sequence, where `check_speculative` applies cleanly onto our tip; an
        // update WE cosigned passes (we checked it), so honest flow never arms.
        // Never accuse ourselves.
        if inbound.update.operator_id != self.node_id && !inbound.update.cosignatures.is_empty() {
            // `Some(governing QuorumBegin seq)` when non-conforming: the
            // contagion proofs below name it (None if the history we hold
            // shows none, and then there are no proofs to build).
            let non_conforming: Option<Option<u64>> = {
                let l = ledger_arc.read().unwrap();
                // A replica replayed across a hole in its JSONL holds wrong
                // balances; it does not judge (ref3 disputed C at 67860 so).
                if inbound.update.operator_id == l.state.parent_pubkey
                    && inbound.update.sequence_number == l.next_sequence()
                    && !self.handler.is_damaged(&inbound.ledger_id)
                {
                    deposits_core::messages::LedgerOperation::tlv_decode(&inbound.update.message)
                        .ok()
                        .filter(|op| {
                            let h = self.wallet.get_block_height().unwrap_or(0);
                            !l.state
                                .check_speculative(
                                    op,
                                    &deposits_core::dep16::Dep16Authorizer::new(),
                                    h,
                                )
                                .is_empty()
                        })
                        .map(|_| {
                            deposits_core::fraud::governing_quorum_begin_seq(
                                &l.history,
                                &inbound.update,
                            )
                        })
                } else {
                    None
                }
            };
            if let Some(governing_qb) = non_conforming {
                let last_valid = inbound.update.sequence_number.saturating_sub(1);
                tracing::warn!(
                    "NON-CONFORMING COSIGNED update on {}... seq {}: quorum cosigned an update that fails conformance — arming dispute",
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    inbound.update.sequence_number,
                );
                let node = std::sync::Arc::clone(self);
                let ledger_id = inbound.ledger_id.clone();
                let fault = inbound.update.clone();
                tokio::spawn(async move {
                    if let Err(e) = node
                        .auto_arm_for_dispute_with_anchor(&ledger_id, last_valid, None)
                        .await
                    {
                        tracing::error!(
                            "Non-conforming-cosig: failed to arm dispute on {}...: {}",
                            &ledger_id[..16.min(ledger_id.len())],
                            e
                        );
                    }
                    match governing_qb {
                        Some(qb) => node.broadcast_contagion(&fault, qb).await,
                        None => tracing::warn!(
                            "Non-conforming-cosig on {}... seq {}: no QuorumBegin at or before \
                             it in our history — no contagion proofs",
                            &ledger_id[..16.min(ledger_id.len())],
                            fault.sequence_number
                        ),
                    }
                });
            }
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
            let is_from_operator = inbound.update.operator_id == ledger.state.parent_pubkey;
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

        let (is_from_operator, is_from_active_member, is_dispute_enter, in_dispute) = sender_role;

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
                }) =
                    deposits_core::messages::LedgerOperation::tlv_decode(&inbound.update.message)
                {
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
        // — don't echo the disputer's; commit to what we observe. Use
        // `fetch_block_info()` (live chain query) rather than
        // `get_block_height()` (returns the wallet's cached value),
        // because BDK's background sync lags far behind the live tip
        // during burst-mining: the daemon's chain_backend may already
        // confirm the disputer's anchor (live) while the wallet cache is
        // still hundreds of blocks behind. Recording the stale cached
        // height as our own anchor produces an anchor < quorum_expiry —
        // the very predicate we just verified the disputer's anchor
        // satisfies — and peers refuse to arm against our fork.
        let (our_height, our_hash) = self.wallet.fetch_block_info().unwrap_or((0, [0u8; 32]));
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

    /// Fully verify a fraud broadcast against our own view of the world.
    ///
    /// A fraud notice (kind:9101, or one re-fetched off the relay during a
    /// confiscation decision) is a SIGNAL to verify, never authoritative on its
    /// own — anyone can publish a well-formed-looking `FraudBroadcast` carrying
    /// any `proof_type`. This gap-fills the referenced ledgers from the relay,
    /// then runs the protocol-layer `verify_fraud_broadcast` (per-type
    /// evidence, plus structural + embedding + causal chain for
    /// embedding-required types) plus the
    /// `WinnerCollateralDeviation` on-chain step. `Ok(())` means the fault is
    /// real. Shared by the inbound receive path (`handle_fraud_proof`) and the
    /// confiscation proof-type resolver so both ground on identical checks.
    pub(crate) async fn verify_fraud_broadcast_locally(
        &self,
        broadcast: &deposits_core::fraud::FraudBroadcast,
    ) -> Result<(), String> {
        // 0. Gap-fill any referenced ledgers we don't already have.
        //    `verify_fraud_broadcast` queries the LedgerProvider for the
        //    accused ledger, the embedding ledger AND every causal-chain
        //    link's ledger (the latter two only for embedding-required
        //    types); missing → reject. Cosigners only hold replicas of
        //    ledgers they joined, so pre-fetch from the durable relay before
        //    verifying. A self-evident proof may carry no embedding, so the
        //    accused ledger is named explicitly.
        let mut needed: std::collections::HashSet<String> =
            std::iter::once(broadcast.proof.ledger_id.clone()).collect();
        if broadcast.proof.proof_type.requires_embedding() {
            if let Some(embedding) = &broadcast.embedding {
                needed.insert(embedding.ledger_id.clone());
            }
            for link in &broadcast.causal_chain {
                needed.insert(link.ledger_id.clone());
            }
        }
        // Evidence can name further ledgers whose history its verifier
        // replays: NonConformingCosignature's fault ledger, and the member
        // ledger of StaleCosign / DisputeDereliction.
        match &broadcast.proof.evidence {
            deposits_core::fraud::FraudEvidence::NonConformingCosignature {
                fault_ledger_id,
                ..
            } => {
                needed.insert(fault_ledger_id.clone());
            }
            deposits_core::fraud::FraudEvidence::UnauthorizedVaultSpend {
                spent_ledger_id,
                ..
            } => {
                needed.insert(spent_ledger_id.clone());
            }
            deposits_core::fraud::FraudEvidence::StaleCosign {
                member_ledger_id, ..
            }
            | deposits_core::fraud::FraudEvidence::DisputeDereliction {
                member_ledger_id, ..
            } => {
                needed.insert(member_ledger_id.clone());
            }
            _ => {}
        }
        for lid in &needed {
            let have = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers.contains_key(lid)
            };
            if have {
                continue;
            }
            if let Err(e) = self.reimport_joined_ledger(lid).await {
                tracing::warn!(
                    "Fraud-proof gap-fill failed for ledger {}: {} \
                     (verification will refuse if this ledger is referenced)",
                    &lid[..16.min(lid.len())],
                    e
                );
            }
        }

        // Structural + embedding + causal chain + per-type evidence — all in
        // the protocol-layer verifier so unit tests exercise the same path.
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
        // `confirms_block` fails closed (None on unknown / not-best-chain /
        // network error), so the verifier's chain checks can't be spoofed.
        struct WalletOracle<'a> {
            wallet: &'a crate::wallet::Wallet,
        }
        impl<'a> deposits_core::fraud::BlockOracle for WalletOracle<'a> {
            fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
                self.wallet.confirms_block(hash)
            }
        }

        // Synchronous structural + embedding + causal + per-type evidence
        // check. provider/oracle are created and used entirely within these
        // sync calls (no await follows), so no non-Send guard is held across
        // an await — keeps this helper usable from spawned (Send) tasks like
        // the confiscation driver.
        let provider = DaemonLedgers {
            handler: &self.handler,
        };
        let oracle = WalletOracle {
            wallet: &self.wallet,
        };
        // Witnesses are judged with the dep-16 descriptor verifier, the one
        // the replica's apply_and_check uses: a proof of a forged spend
        // verifies here whether or not we watched the update land.
        let authorizer = deposits_core::dep16::Dep16Authorizer::new();
        deposits_core::fraud::verify_fraud_broadcast(broadcast, &provider, &oracle, &authorizer)?;

        // WinnerCollateralDeviation's evidence is the on-chain claim TX,
        // which the pure verifier can't fetch. The type is self-evident, so
        // no embedding check stands in for it: both the receive path and the
        // confiscation resolver must run this step.
        // UnauthorizedVaultSpend's witness check needs the reserves tapscript
        // tree, which lives in deposits-core: run it here against the spent
        // ledger's replica. Excused: the recorded rotations, and a confiscation
        // we built ourselves (no QuorumBegin records it).
        if let deposits_core::fraud::FraudEvidence::UnauthorizedVaultSpend {
            spent_ledger_id, ..
        } = &broadcast.proof.evidence
        {
            use deposits_core::fraud::LedgerProvider;
            let history = provider
                .ledger_history(spent_ledger_id)
                .ok_or("UnauthorizedVaultSpend: spent ledger not available")?;
            let known_confiscations: Vec<[u8; 32]> = self
                .known_confiscation_txids
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect();
            deposits_core::vault_spend::verify_unauthorized_vault_spend(
                &broadcast.proof,
                &history,
                &known_confiscations,
            )
            .map_err(|e| format!("UnauthorizedVaultSpend: {}", e))?;
        }

        if matches!(
            broadcast.proof.proof_type,
            deposits_core::fraud::FraudProofType::WinnerCollateralDeviation
        ) {
            self.verify_winner_collateral_deviation_onchain(broadcast, &oracle)
                .map_err(|e| format!("WinnerCollateralDeviation: {}", e))?;
        }
        Ok(())
    }

    /// Handle an incoming fraud proof broadcast.
    ///
    /// Verifies the proof (its evidence, plus the embedding and causal chain
    /// for embedding-required types), then checks if we're a quorum member.
    /// If so, initiates a custody dispute.
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

        // A fraud notice is a SIGNAL, not authoritative: fully verify it
        // (gap-fill + structural/embedding/causal/per-type evidence + the
        // on-chain WinnerCollateralDeviation step) before acting on it.
        let proof_hash_hex = hex::encode(broadcast.proof.proof_hash());
        if let Err(e) = self.verify_fraud_broadcast_locally(broadcast).await {
            tracing::warn!("Fraud proof rejected ({}...): {}", &proof_hash_hex[..16], e);
            return;
        }

        match &broadcast.embedding {
            Some(embedding) if broadcast.proof.proof_type.requires_embedding() => {
                tracing::warn!(
                    "Fraud proof VERIFIED: {} at seq {} on {}, evidence type {:?}",
                    &proof_hash_hex[..16],
                    embedding.sequence,
                    &embedding.ledger_id[..16.min(embedding.ledger_id.len())],
                    broadcast.proof.proof_type,
                );
            }
            _ => {
                tracing::warn!(
                    "Fraud proof VERIFIED: {} (self-evident, no embedding), evidence type {:?}",
                    &proof_hash_hex[..16],
                    broadcast.proof.proof_type,
                );
            }
        }

        // A verified proof disputes the ledger only while the accused still
        // operates it. After a confiscation and DisputeAcquire the ledger
        // continues under the new custodian (`parent_pubkey`); anyone can
        // re-broadcast the old, already-punished proof, and it still
        // verifies (the accused did operate the ledger at the fault's
        // sequence), but acting on it would freeze the honest successor.
        // Verification is unchanged: this only decides whether to act.
        let current_operator = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().state.parent_pubkey)
        };
        if !fraud_proof_accuses_current_operator(&broadcast.proof.accused, current_operator.as_ref())
        {
            tracing::info!(
                "Not disputing {}: proof against a former operator; custody already moved \
                 (accused {}, current operator {})",
                &ledger_id[..16.min(ledger_id.len())],
                &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
                current_operator
                    .map(|k| hex::encode(&k.serialize()[..8]))
                    .unwrap_or_else(|| "unknown: ledger not held".into()),
            );
            return;
        }

        // Contagion targets the accused's *other* ledgers. A
        // NonConformingCosignature against its own fault ledger (the
        // operator accused, as cl's receiver and ours both exclude but
        // anyone may broadcast) is not a second dispute there: that ledger
        // is judged by its own NonConformingUpdate dispute, from before the
        // fault, armed when the fault arrived.
        if contagion_proof_on_its_fault_ledger(&broadcast.proof.evidence, ledger_id) {
            tracing::info!(
                "Not disputing {} on a contagion proof: it is the fault ledger, \
                 judged by its own dispute from before the fault",
                &ledger_id[..16.min(ledger_id.len())],
            );
            return;
        }

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

        // 5. Determine last valid sequence from the proof: the fault's
        //    predecessor wherever the proof names a fault on this ledger,
        //    never the replica's tip past it (auto_arm also clamps to the
        //    first update the replica flagged).
        let replica_tip = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().next_sequence().saturating_sub(1))
                .unwrap_or(0)
        };
        let last_valid_seq =
            fraud_proof_last_valid_seq(&broadcast.proof.evidence, ledger_id, replica_tip);

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

                // DEP-19 §6: having disputed on a *punitive* proof, start a
                // dereliction watch on the faulted ledger. A periodic task
                // scans the ledger's OTHER quorum members once their response
                // window elapses and accuses any that stayed active without
                // acting. Respectful (QuorumExpired) faults don't cascade, and
                // a DisputeDereliction isn't itself watched (no second-order
                // cascade).
                if !broadcast.proof.proof_type.is_respectful()
                    && !matches!(
                        broadcast.proof.proof_type,
                        deposits_core::fraud::FraudProofType::DisputeDereliction
                    )
                {
                    if let Some(visible_block_hash) =
                        self.dereliction_visible_block_hash(broadcast)
                    {
                        self.register_dereliction_watch(
                            ledger_id,
                            broadcast.proof.proof_hash(),
                            visible_block_hash,
                        );
                    }
                }

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
    fn verify_winner_collateral_deviation_onchain(
        &self,
        broadcast: &deposits_core::fraud::FraudBroadcast,
        oracle: &dyn deposits_core::fraud::BlockOracle,
    ) -> Result<(), String> {
        let claim_txid_str = match &broadcast.proof.evidence {
            deposits_core::fraud::FraudEvidence::WinnerCollateralDeviation {
                claim_txid, ..
            } => claim_txid.clone(),
            _ => return Err("evidence type mismatch".into()),
        };
        let claim_txid_bytes_vec =
            hex::decode(&claim_txid_str).map_err(|e| format!("claim_txid hex: {}", e))?;
        let claim_txid_bytes: [u8; 32] = claim_txid_bytes_vec
            .try_into()
            .map_err(|_| "claim_txid: expected 32 bytes".to_string())?;
        let claim_txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(claim_txid_bytes));
        let claim_tx = self
            .wallet
            .get_transaction(claim_txid)
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
    /// Takes the Partner copy's history up to `last_valid_seq`, rebuilds the
    /// state there from genesis (`fork_state_at`: nothing is inherited from
    /// the Partner copy's current state, which may include the fault), and
    /// stores the fork under a compound tracking key. The original Partner
    /// copy stays untouched for evidence/auditing.
    ///
    /// Returns the compound tracking key for the fork.
    pub(crate) fn create_dispute_fork(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
    ) -> Result<String, Error> {
        use crate::handler::DepositsHandler;

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

        // Rebuild the fork's state as of `last_valid_seq` from genesis.
        //
        // The fork's state is the ledger AT THE FORK POINT: everything the
        // dispute computes from it (the replacement-collateral floor in
        // auto-arm, and the recovered ledger's balances) must exclude the
        // fault. It used to be `original.state.clone()` with a few fields
        // cleared and the prefix replayed on top, but the base replica has
        // applied the faulty update (see `LedgerActor::apply_inbound`), and
        // the clone kept every field the reset list missed, among them the
        // cached `total_deposit_balance`. Replay then ADDED the prefix's
        // balances to the post-fault total: on ledger C, 40,480,000,000 msat
        // (after a fraudulent 40,000,000,000 credit) + 480,000,000 replayed,
        // so ref3 demanded 61,445,000 sats of replacement collateral where
        // 725,000 was right, and armed without any.
        //
        // In-memory history is capped (`history_retain`), so when it no
        // longer reaches genesis the chain comes from the on-disk JSONL.
        let replay_chain: Vec<deposits_core::SignedLedgerUpdate> =
            if original.history.first().map(|u| u.sequence_number) == Some(0) {
                truncated_history.clone()
            } else {
                self.handler
                    .read_persisted_history(ledger_id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|u| u.sequence_number <= last_valid_seq)
                    .collect()
            };
        let fork_state = match fork_state_at(&original.state, &replay_chain, last_valid_seq) {
            Some(state) => state,
            None => {
                return Err(Error::Protocol(format!(
                    "cannot rebuild ledger {} at fork point {}: no LedgerOpen (seq 0) \
                     in memory or on disk",
                    &ledger_id[..16.min(ledger_id.len())],
                    last_valid_seq
                )));
            }
        };

        let fork = Ledger {
            state: fork_state,
            protocol: Default::default(),
            role: deposits_core::ledger::LedgerRole::Operator, // We operate the fork
            history: truncated_history,
            created_at: Default::default(),
        };
        drop(original);

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

/// The ledger's state at `last_valid_seq`, replayed from a FRESH state over
/// `chain` (the base replica's updates, oldest first). Nothing is carried over
/// from `current`, which may already include the fault being disputed, except
/// `reserves_outpoint`, which no operation sets. `None` when `chain` does not
/// start with the seq-0 `LedgerOpen`, since then there is nothing to replay from.
///
/// Mirrors `Ledger::recompute_state` (the same per-update post-hooks), but a
/// single op that fails to apply is logged and skipped rather than aborting,
/// as the JSONL loader does, so a quirk deep in a long history cannot stop an
/// honest member from disputing.
pub(crate) fn fork_state_at(
    current: &deposits_core::types::LedgerState,
    chain: &[deposits_core::SignedLedgerUpdate],
    last_valid_seq: u64,
) -> Option<deposits_core::types::LedgerState> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::types::LedgerState;
    use deposits_core::TlvDecode;

    let genesis = chain.first().filter(|u| u.sequence_number == 0)?;
    let (operator_id, reserves_id, genesis_block) =
        match LedgerOperation::tlv_decode(&genesis.message) {
            Ok(LedgerOperation::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                ..
            }) => (operator_id, reserves_id, genesis_block),
            _ => return None,
        };
    let mut state = LedgerState::new(operator_id, reserves_id, genesis_block);
    for update in chain.iter().filter(|u| u.sequence_number <= last_valid_seq) {
        if let Err(e) = state.apply_update_in_place(update) {
            tracing::warn!(
                "Fork replay seq {}: failed to apply: {}",
                update.sequence_number,
                e
            );
        }
    }
    state.reserves_outpoint = current.reserves_outpoint.clone();
    Some(state)
}

/// `advertised` then `held`, first occurrence kept, only 64-hex ledger ids.
pub(crate) fn merge_ledger_ids(advertised: Vec<String>, held: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in advertised.into_iter().chain(held) {
        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) && !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// The sequence a dispute started from a verified fraud proof on
/// `ledger_id` forks after. Where the evidence names a fault on this ledger
/// that is its predecessor (cl: `(1- fault-sequence)`): NonConformingUpdate's
/// `fault_sequence`, Equivocation's `sequence`, the uncredited payments'
/// `proof_sequence`, NonConforming's `sequence`, and NonConformingCosignature's
/// `fault_sequence` when the fault ledger is this one. Otherwise the chain is
/// valid up to `replica_tip`: QuorumExpired (a deadline miss), a
/// NonConformingCosignature on another ledger (cross-ledger contagion: this
/// ledger's own chain is intact), and the rest. Before this, NonConformingUpdate
/// fell to the replica tip: ref3 disputed C's fault at 17,840 from 20,181.
pub(crate) fn fraud_proof_last_valid_seq(
    evidence: &deposits_core::fraud::FraudEvidence,
    ledger_id: &str,
    replica_tip: u64,
) -> u64 {
    use deposits_core::fraud::FraudEvidence as E;
    let fault = match evidence {
        E::NonConformingUpdate { fault_sequence, .. } => Some(*fault_sequence),
        E::Equivocation { sequence, .. } => Some(*sequence),
        E::UncreditedOnchain { proof_sequence, .. } => Some(*proof_sequence),
        E::UncreditedLightning { proof_sequence, .. } => Some(*proof_sequence),
        E::NonConforming { sequence, .. } => Some(*sequence),
        E::NonConformingCosignature {
            fault_ledger_id,
            fault_sequence,
            ..
        } if fault_ledger_id.eq_ignore_ascii_case(ledger_id) => Some(*fault_sequence),
        _ => None,
    };
    match fault {
        Some(seq) => seq.saturating_sub(1),
        None => replica_tip,
    }
}

/// Whether `evidence` is a `NonConformingCosignature` (contagion) presented
/// against its own fault ledger. Contagion disputes the accused's *other*
/// ledgers; the fault ledger is judged by its own dispute from before the
/// fault, so such a proof must not start a second one there. With operator
/// contagion the accused is the fault ledger's current operator, so the
/// stale-proof rule alone would let it through.
pub(crate) fn contagion_proof_on_its_fault_ledger(
    evidence: &deposits_core::fraud::FraudEvidence,
    ledger_id: &str,
) -> bool {
    matches!(
        evidence,
        deposits_core::fraud::FraudEvidence::NonConformingCosignature { fault_ledger_id, .. }
            if fault_ledger_id.eq_ignore_ascii_case(ledger_id)
    )
}

/// Whether a verified fraud proof accuses the ledger's current operator
/// (`parent_pubkey` of our replica), the only case in which it may dispute
/// the ledger. A proof against a former operator, whose custody has already
/// moved at a DisputeAcquire, is stale: acting on it would dispute the new
/// custodian for its predecessor's fault. An unknown operator (ledger not
/// held) or an unparseable `accused` is not acted on either.
pub(crate) fn fraud_proof_accuses_current_operator(
    accused_hex: &str,
    current_operator: Option<&bitcoin::secp256k1::PublicKey>,
) -> bool {
    current_operator.is_some_and(|op| {
        hex::decode(accused_hex).is_ok_and(|a| a[..] == op.serialize()[..])
    })
}

/// Whether `update` belongs to ledger `ledger_id`, whose `history` we hold,
/// by what its operator signed: a genesis opening that ledger, or an
/// update whose `previous_hash` is one of our updates' `chain_hash`. Its
/// `ledger_id` field says nothing: no signature covers it, and one operator
/// key runs several ledgers (a cl node signs its own ledger and the one it
/// operates with its node key), so anyone can republish an honest update of
/// the operator's other ledger tagged as this one, at a sequence we hold.
/// Without this, that looked like double-signing and armed a dispute.
pub(crate) fn inbound_binds_to_ledger(
    update: &deposits_core::types::SignedLedgerUpdate,
    ledger_id: &[u8; 32],
    history: &[deposits_core::types::SignedLedgerUpdate],
) -> bool {
    if update.sequence_number == 0 {
        return deposits_core::fraud::update_opens_ledger(update, ledger_id);
    }
    history
        .iter()
        .rev()
        .any(|h| h.chain_hash() == update.previous_hash)
}

/// Two updates double-sign the same slot: same ledger + sequence + operator,
/// but different `content_hash`. That's provable equivocation (each bears the
/// operator's signature). Pure so it's unit-testable; `verify_equivocation`
/// re-checks the same invariant on every receiver (defense in depth), so a
/// false positive here can't drive a confiscation on its own.
pub(crate) fn updates_equivocate(
    a: &deposits_core::types::SignedLedgerUpdate,
    b: &deposits_core::types::SignedLedgerUpdate,
) -> bool {
    a.ledger_id == b.ledger_id
        && a.sequence_number == b.sequence_number
        && a.operator_id == b.operator_id
        && a.content_hash != b.content_hash
}

#[cfg(test)]
mod contagion_target_tests {
    use super::merge_ledger_ids;

    #[test]
    fn advertised_and_held_ledgers_merge_without_duplicates() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let merged = merge_ledger_ids(
            vec![a.clone(), b.clone(), a.clone(), "short".into(), "z".repeat(64)],
            vec![b.clone(), c.clone()],
        );
        assert_eq!(merged, vec![a, b, c]);
    }
}

#[cfg(test)]
mod fraud_proof_base_tests {
    use super::{
        contagion_proof_on_its_fault_ledger, fraud_proof_accuses_current_operator,
        fraud_proof_last_valid_seq,
    };
    use deposits_core::fraud::FraudEvidence;

    fn key(b: u8) -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    /// Ledger A was taken over: cld1's forged update at seq 6969 was
    /// disputed and confiscated, and cld3 acquired custody. The old proof
    /// against cld1 still verifies when re-broadcast, but it must not
    /// dispute A again under cld3. A proof against cld3 still does.
    #[test]
    fn a_proof_against_a_former_operator_does_not_dispute_the_successor() {
        let (cld1, cld3) = (key(1), key(3));
        let accuses = |k: bitcoin::secp256k1::PublicKey| hex::encode(k.serialize());
        assert!(!fraud_proof_accuses_current_operator(&accuses(cld1), Some(&cld3)));
        assert!(fraud_proof_accuses_current_operator(&accuses(cld3), Some(&cld3)));
        assert!(fraud_proof_accuses_current_operator(&accuses(cld1), Some(&cld1)));
        // Nothing to judge against, or garbage: not acted on.
        assert!(!fraud_proof_accuses_current_operator(&accuses(cld1), None));
        assert!(!fraud_proof_accuses_current_operator("zz", Some(&cld1)));
    }

    const C: &str = "ab";

    /// ref3 verified cl's NonConformingUpdate proof of ledger C's seq 17,840
    /// and initiated a dispute at last_valid_seq=20181, its replica's tip.
    #[test]
    fn a_verified_proof_forks_before_its_fault_not_at_the_replica_tip() {
        let ncu = FraudEvidence::NonConformingUpdate {
            fault_sequence: 17_840,
            fault_update_hex: String::new(),
        };
        assert_eq!(fraud_proof_last_valid_seq(&ncu, C, 20_181), 17_839);
        let equivocation = FraudEvidence::Equivocation {
            sequence: 17_840,
            update_a_hex: String::new(),
            update_b_hex: String::new(),
        };
        assert_eq!(fraud_proof_last_valid_seq(&equivocation, C, 20_181), 17_839);
        let cosig = |ledger: &str| FraudEvidence::NonConformingCosignature {
            fault_ledger_id: ledger.to_string(),
            fault_sequence: 17_840,
            governing_quorumbegin_seq: 1,
            fault_update_hex: String::new(),
        };
        // On this ledger: before the fault. On another (contagion): this
        // ledger's chain is intact, so its tip.
        assert_eq!(fraud_proof_last_valid_seq(&cosig("AB"), C, 20_181), 17_839);
        assert_eq!(fraud_proof_last_valid_seq(&cosig("cd"), C, 20_181), 20_181);
    }

    /// Operator contagion: cld1 forges on M. An operator-accused
    /// NonConformingCosignature disputes cld1's other ledger A at A's tip,
    /// but one presented against M itself is not acted on: M is judged by
    /// its own dispute from before the fault, and cld1 is M's current
    /// operator, so the stale-proof rule would not stop a second one.
    #[test]
    fn a_contagion_proof_never_disputes_its_own_fault_ledger_again() {
        let (m, a) = ("ab".repeat(32), "cd".repeat(32));
        let cosig = FraudEvidence::NonConformingCosignature {
            fault_ledger_id: m.clone(),
            fault_sequence: 6_969,
            governing_quorumbegin_seq: 1,
            fault_update_hex: String::new(),
        };
        assert!(contagion_proof_on_its_fault_ledger(&cosig, &m));
        assert!(contagion_proof_on_its_fault_ledger(&cosig, &m.to_uppercase()));
        assert!(!contagion_proof_on_its_fault_ledger(&cosig, &a));
        assert_eq!(fraud_proof_last_valid_seq(&cosig, &a, 7_100), 7_100);
        // The fault ledger's own proof is not contagion: it still disputes.
        let ncu = FraudEvidence::NonConformingUpdate {
            fault_sequence: 6_969,
            fault_update_hex: String::new(),
        };
        assert!(!contagion_proof_on_its_fault_ledger(&ncu, &m));
        assert_eq!(fraud_proof_last_valid_seq(&ncu, &m, 7_100), 6_968);
    }
}

#[cfg(test)]
mod equivocation_detection_tests {
    use super::updates_equivocate;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::types::SignedLedgerUpdate;

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn upd(ledger: [u8; 32], seq: u64, op: PublicKey, content: [u8; 32]) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: Vec::new(),
            message_type: 0,
            operator_id: op,
            ledger_id: ledger,
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: content,
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    /// A relay can republish an honest update of the operator's other ledger
    /// tagged as this one: same operator, same sequence, different content.
    /// It follows nothing we hold, so it is not treated as double-signing;
    /// a sibling of our update, following our predecessor, is.
    #[test]
    fn only_an_update_following_our_chain_binds_to_the_ledger() {
        use super::inbound_binds_to_ledger;
        let (l, op) = ([1u8; 32], pk(0x11));
        let mut ours = vec![upd(l, 0, op, [0x10; 32])];
        for seq in 1..4u64 {
            let mut u = upd(l, seq, op, [0x10 + seq as u8; 32]);
            u.previous_hash = ours.last().unwrap().chain_hash();
            ours.push(u);
        }
        // Our seq 3's sibling, off our seq 2: binds, and equivocates.
        let mut sibling = upd(l, 3, op, [0xCC; 32]);
        sibling.previous_hash = ours[2].chain_hash();
        assert!(inbound_binds_to_ledger(&sibling, &l, &ours));
        assert!(updates_equivocate(&ours[3], &sibling));
        // The other ledger's seq 3, relabelled: equivocates on its face, but
        // follows an update we don't have.
        let mut relabelled = upd(l, 3, op, [0xDD; 32]);
        relabelled.previous_hash = [0x77; 32];
        assert!(updates_equivocate(&ours[3], &relabelled));
        assert!(!inbound_binds_to_ledger(&relabelled, &l, &ours));
        // A seq-0 update binds only if it opens this ledger.
        assert!(!inbound_binds_to_ledger(&upd(l, 0, op, [0xEE; 32]), &l, &ours));
    }

    #[test]
    fn same_slot_different_content_is_equivocation() {
        let (l, op) = ([1u8; 32], pk(0x11));
        let a = upd(l, 11080, op, [0xAA; 32]);
        let b = upd(l, 11080, op, [0xBB; 32]);
        assert!(updates_equivocate(&a, &b));
    }

    #[test]
    fn identical_update_is_not_equivocation() {
        let (l, op) = ([1u8; 32], pk(0x11));
        let a = upd(l, 11080, op, [0xAA; 32]);
        assert!(!updates_equivocate(&a, &a.clone()));
    }

    #[test]
    fn different_sequence_is_not_equivocation() {
        let (l, op) = ([1u8; 32], pk(0x11));
        let a = upd(l, 11080, op, [0xAA; 32]);
        let b = upd(l, 11081, op, [0xBB; 32]);
        assert!(!updates_equivocate(&a, &b));
    }

    #[test]
    fn different_operator_is_not_equivocation() {
        // Two operators colliding on a seq isn't one operator double-signing.
        let l = [1u8; 32];
        let a = upd(l, 11080, pk(0x11), [0xAA; 32]);
        let b = upd(l, 11080, pk(0x22), [0xBB; 32]);
        assert!(!updates_equivocate(&a, &b));
    }

    #[test]
    fn different_ledger_is_not_equivocation() {
        let op = pk(0x11);
        let a = upd([1u8; 32], 11080, op, [0xAA; 32]);
        let b = upd([2u8; 32], 11080, op, [0xBB; 32]);
        assert!(!updates_equivocate(&a, &b));
    }
}

#[cfg(test)]
mod fork_point_collateral_tests {
    //! Finding 9a (cl-deposits REDTEAM, 2026-09-28): a colluding operator's
    //! non-conforming 40,000,000,000 msat credit on ledger C (obligations
    //! 480,000,000 msat, collateral/reserves = 30e9/20e9) made the honest
    //! disputant demand 61,445,000 sats of replacement collateral instead of
    //! 725,000, so it armed without any. DEP-06 §Phase 1 sizes the bond from
    //! obligations at `last_valid_sequence`. These pin both the arming side
    //! (`fork_state_at`) and the cosigner side (`collateral_basis_at`) to that.
    use super::fork_state_at;
    use crate::node::replacement_collateral::{
        collateral_basis_at, compute_required_replacement_sats, CollateralPolicy,
    };
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
    use deposits_core::types::LedgerState;
    use deposits_core::{SignedLedgerUpdate, TlvEncode};

    const RESERVES: u64 = 20_000_000_000;
    const COLLATERAL: u64 = 30_000_000_000;
    const HONEST: u64 = 480_000_000;
    const FRAUD: u64 = 40_000_000_000;
    const LVS: u64 = 3;

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn signed(
        seq: u64,
        operator: PublicKey,
        op: &LedgerOperation,
        prev: [u8; 32],
    ) -> SignedLedgerUpdate {
        let message = op.tlv_encode();
        let mut u = SignedLedgerUpdate {
            message,
            message_type: 0x8001,
            operator_id: operator,
            ledger_id: [7u8; 32],
            sequence_number: seq,
            previous_hash: prev,
            content_hash: [0u8; 32],
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            operator_signature: [seq as u8 + 1; 64],
            cosignatures: Vec::new(),
        };
        u.content_hash = u.compute_hash();
        u
    }

    fn credit(n: u8, amount: u64) -> LedgerOperation {
        LedgerOperation::OnchainCredit {
            txid: [n; 32],
            vout: 0,
            deposit_id: [0xAB; 16],
            amount,
            funding_address: "bcrt1qfund".to_string(),
            commitment: None,
        }
    }

    /// seq 0 LedgerOpen, 1 QuorumBegin, 2 DepositOpen, 3 the honest credit
    /// (the last valid update), 4 the fraudulent credit.
    fn ledger_c() -> (PublicKey, Vec<SignedLedgerUpdate>) {
        let operator = pk(1);
        let ops = vec![
            LedgerOperation::LedgerOpen {
                operator_id: operator,
                reserves_id: "bcrt1qreserves".to_string(),
                genesis_block: 0,
                reserves_amount: RESERVES,
                collateral_amount: COLLATERAL,
            },
            LedgerOperation::QuorumBegin {
                reserves_id: "bcrt1qreserves".to_string(),
                spending_txid: [0; 32],
                new_outpoint_txid: [1; 32],
                new_outpoint_vout: 0,
                amount: RESERVES,
                quorum_expiry: 1_000_000,
                ledger_hash: [0; 32],
                quorum_members: vec![QuorumMemberRef::pubkey_only(pk(2))],
                collateral_amount: COLLATERAL,
                protocol_version: None,
            },
            LedgerOperation::DepositOpen {
                deposit_id: [0xAB; 16],
                descriptor: "wpkh(deadbeef)".to_string(),
                fees: None,
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
                commitment: None,
            },
            credit(1, HONEST),
            credit(2, FRAUD),
        ];
        let mut chain = Vec::new();
        let mut prev = [0u8; 32];
        for (seq, op) in ops.iter().enumerate() {
            let u = signed(seq as u64, operator, op, prev);
            prev = u.chain_hash();
            chain.push(u);
        }
        (operator, chain)
    }

    /// The base replica's state: it applies the non-conforming update too
    /// (`LedgerActor::apply_inbound` logs the violations and applies).
    fn base_state(operator: PublicKey, chain: &[SignedLedgerUpdate]) -> LedgerState {
        use deposits_core::TlvDecode;
        let mut state = LedgerState::new(operator, String::new(), 0);
        for u in chain {
            state
                .apply_in_place(&LedgerOperation::tlv_decode(&u.message).unwrap())
                .unwrap();
            state.sequence = u.sequence_number;
            state.chain_tip_hash = u.chain_hash();
        }
        state
    }

    fn required(obligations: u64) -> u64 {
        compute_required_replacement_sats(
            obligations,
            COLLATERAL,
            RESERVES,
            &CollateralPolicy::default(),
        )
        .unwrap()
    }

    #[test]
    fn fork_state_is_the_fork_point_not_the_faulted_base() {
        let (operator, chain) = ledger_c();
        let base = base_state(operator, &chain);
        assert_eq!(base.total_deposit_balance(), HONEST + FRAUD);

        let fork = fork_state_at(&base, &chain, LVS).unwrap();
        assert_eq!(fork.total_deposit_balance(), HONEST);
        assert_eq!(
            fork.fold_deposit_balance(),
            HONEST,
            "cache matches the deposits map"
        );
        assert_eq!(fork.sequence, LVS);
        assert_eq!(fork.chain_tip_hash, chain[LVS as usize].chain_hash());
        assert_eq!(
            (fork.collateral_amount, fork.reserves_amount),
            (COLLATERAL, RESERVES)
        );
        assert_eq!(fork.quorum_begin_sequence, Some(1));
    }

    #[test]
    fn required_collateral_uses_obligations_at_the_fork_point() {
        let (operator, chain) = ledger_c();
        let base = base_state(operator, &chain);
        let fork = fork_state_at(&base, &chain, LVS).unwrap();

        // 480,000,000 msat × 1.5 / 1000 + 5,000: what cl pledged against.
        let at_fork = required(fork.total_deposit_balance());
        assert_eq!(at_fork, 725_000);
        // The faulted tip would demand 60,725,000; the old fork rebuild
        // (clone of the base, deposits cleared, cached total NOT cleared,
        // prefix replayed on top) demanded 61,445,000, the logged figure.
        assert_eq!(required(base.total_deposit_balance()), 60_725_000);
        assert_eq!(required(HONEST + FRAUD + HONEST), 61_445_000);
        assert!(at_fork < required(base.total_deposit_balance()));
    }

    #[test]
    fn fork_state_ignores_the_callers_current_state() {
        // Whatever the base replica holds (here a cached total the replay
        // must not add to), the rebuild starts fresh.
        let (operator, chain) = ledger_c();
        let mut base = base_state(operator, &chain);
        base.total_deposit_balance = u64::MAX / 2;
        base.fees_accumulated = 12345;
        let fork = fork_state_at(&base, &chain[..=LVS as usize], LVS).unwrap();
        assert_eq!(fork.total_deposit_balance(), HONEST);
        assert_eq!(fork.fees_accumulated, 0);
    }

    #[test]
    fn fork_state_needs_genesis() {
        let (operator, chain) = ledger_c();
        let base = base_state(operator, &chain);
        assert!(fork_state_at(&base, &chain[1..], LVS).is_none());
    }

    #[test]
    fn cosigner_basis_is_the_fork_point_and_agrees_with_the_armer() {
        let (operator, mut chain) = ledger_c();
        // A disputant's fork-branch updates past lvs are on the relay too.
        let disputant = pk(3);
        chain.push(signed(LVS + 1, disputant, &credit(9, FRAUD), [9; 32]));
        chain.sort_by_key(|u| (u.sequence_number, u.operator_id));

        let basis = collateral_basis_at(&chain, operator, LVS).unwrap();
        assert_eq!(basis.obligations_msat, HONEST);
        assert_eq!(
            (
                basis.qb_collateral_msat,
                basis.qb_reserves_msat,
                basis.qb_seq
            ),
            (COLLATERAL, RESERVES, 1)
        );
        let policy = CollateralPolicy::default();
        assert_eq!(basis.required_sats(&policy), Some(725_000));

        // Armer and cosigner size the bond the same way.
        let base = base_state(
            operator,
            &chain
                .iter()
                .filter(|u| u.operator_id == operator)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let fork = fork_state_at(
            &base,
            &chain
                .iter()
                .filter(|u| u.operator_id == operator)
                .cloned()
                .collect::<Vec<_>>(),
            LVS,
        )
        .unwrap();
        assert_eq!(
            compute_required_replacement_sats(
                fork.total_deposit_balance(),
                fork.collateral_amount,
                fork.reserves_amount,
                &policy
            ),
            basis.required_sats(&policy)
        );

        // At the faulted tip the basis would include the fraud.
        let tip = collateral_basis_at(&chain, operator, LVS + 1).unwrap();
        assert_eq!(tip.obligations_msat, HONEST + FRAUD);
    }

    #[test]
    fn cosigner_basis_refuses_without_a_quorum_begin() {
        let (operator, chain) = ledger_c();
        assert!(collateral_basis_at(&chain, operator, 0).is_err());
    }
}
