use super::*;

/// Terms the operator proposes to a candidate member as part of `quorum_add`.
/// The member echoes any accepted terms back inside its signed
/// `QuorumMemberResponse` blob (see `process_consent_request`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConsentProposedTerms<'a> {
    pub chosen_ruleset: &'a str,
    pub min_fee_bps: Option<u16>,
    pub min_fee_fixed: Option<u64>,
    pub max_fee_period: Option<u32>,
    pub membership_until: Option<u32>,
}

impl Node {
    /// Find the ledger_id for a specific deposit offer
    pub(crate) fn find_ledger_for_offer(&self, offer_id: &[u8; 32]) -> Option<String> {
        // Get the offer to find its ledger_id
        let (offer, _) = self.get_deposit_offer(offer_id)?;

        // The offer already contains the ledger_id, just verify it exists
        let ledgers = self.handler.ledgers.lock().unwrap();
        if ledgers.contains_key(&offer.ledger_id) {
            return Some(offer.ledger_id.clone());
        }
        None
    }

    /// Handle co-sign responses only (sync, to avoid recursion in request_cosign polling)
    ///
    /// This is a simplified version of handle_ledger_response that only processes
    /// co-sign responses. Used inside request_cosign to avoid the recursive call:
    /// request_cosign -> handle_ledger_response -> sign_and_broadcast -> request_cosign
    pub(crate) fn handle_cosign_response_only(&self, response: crate::nostr::LedgerResponse) {
        use std::str::FromStr;
        // For error responses, don't remove the pending request - keep waiting for success.
        // This is important because co-sign requests are multicast and non-quorum-members
        // will respond with errors before the actual quorum member responds.
        if !response.success {
            let has_pending = {
                let pending = self.pending_cosign_requests.lock().unwrap();
                pending.contains_key(&response.request_id)
            };
            if has_pending {
                tracing::debug!(
                    "Ignoring error co-sign response for {}: {} (waiting for quorum member)",
                    &response.request_id[..16.min(response.request_id.len())],
                    response.error.as_deref().unwrap_or("unknown error")
                );
            }
            return;
        }

        // Accumulate in collector (don't remove — more responses may come)
        let collector = {
            let pending = self.pending_cosign_requests.lock().unwrap();
            pending.get(&response.request_id).map(|(_, c)| c.clone())
        };

        if let Some(collector) = collector {
            // This is a successful co-sign response

            if let Some(result) = &response.result {
                let result_obj = if result.is_object() {
                    result.clone()
                } else if let Some(s) = result.as_str() {
                    serde_json::from_str(s).unwrap_or_default()
                } else {
                    tracing::warn!("Co-sign response result is not an object or string");
                    return;
                };

                let sig_hex = result_obj
                    .get("cosign_signature_hex")
                    .and_then(|v| v.as_str());
                let hash_hex = result_obj
                    .get("member_ledger_hash_hex")
                    .and_then(|v| v.as_str());
                let cosigner_str = result_obj.get("cosigner_pubkey").and_then(|v| v.as_str());

                if let (Some(sig_hex), Some(hash_hex)) = (sig_hex, hash_hex) {
                    if let (Ok(sig_vec), Ok(hash_vec)) =
                        (hex::decode(sig_hex), hex::decode(hash_hex))
                    {
                        if sig_vec.len() == 64 && hash_vec.len() == 32 {
                            let mut sig = [0u8; 64];
                            sig.copy_from_slice(&sig_vec);
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&hash_vec);

                            let cosigner_pubkey = cosigner_str
                                .and_then(|s| PublicKey::from_str(s).ok())
                                .unwrap_or(self.node_id); // fallback for old responders

                            let cosign_result = CoSignResult {
                                cosign_signature: sig,
                                cosigner_pubkey,
                                member_ledger_hash: hash,
                                t1_recv_us: result_obj.get("t1_recv_us").and_then(|v| v.as_u64()),
                                t2_send_us: result_obj.get("t2_send_us").and_then(|v| v.as_u64()),
                            };
                            collector.add(cosign_result);
                        } else {
                            tracing::warn!("Co-sign response has wrong signature/hash lengths");
                        }
                    } else {
                        tracing::warn!("Co-sign response has invalid hex encoding");
                    }
                } else {
                    tracing::warn!(
                        "Co-sign response missing cosign_signature_hex or member_ledger_hash_hex"
                    );
                }
            } else {
                tracing::warn!("Co-sign response has no result");
            }
            // Failed to parse — collector stays, awaiting other responses
        }
        // Non-cosign responses are not handled here - they'll be processed later by handle_ledger_response
    }

    /// Handle a ledger response (for auto-recording attestations and co-sign responses)
    pub(crate) async fn handle_ledger_response(&self, response: crate::nostr::LedgerResponse) {
        // First, check if this is a response to a pending co-sign request
        // For error responses, don't remove - keep waiting for success from actual quorum member
        let is_cosign_request = {
            let pending = self.pending_cosign_requests.lock().unwrap();
            pending.contains_key(&response.request_id)
        };

        if is_cosign_request {
            if !response.success {
                // Ignore error responses - non-quorum-members respond with errors
                // but we need to wait for the actual quorum member's success response
                tracing::debug!(
                    "Ignoring error co-sign response for {}: {} (waiting for quorum member)",
                    &response.request_id[..16.min(response.request_id.len())],
                    response.error.clone().unwrap_or_default()
                );
                return;
            }

            // Accumulate in collector (don't remove from map — more responses may come)
            let collector = {
                let pending = self.pending_cosign_requests.lock().unwrap();
                pending.get(&response.request_id).map(|(_, c)| c.clone())
            };

            if let Some(collector) = collector {
                // This is a successful co-sign response
                if let Some(result) = &response.result {
                    let result_obj = if result.is_object() {
                        result.clone()
                    } else if let Some(s) = result.as_str() {
                        serde_json::from_str(s).unwrap_or_default()
                    } else {
                        serde_json::Value::Null
                    };

                    // Extract cosign_signature_hex
                    let sig_hex = result_obj
                        .get("cosign_signature_hex")
                        .and_then(|v| v.as_str());
                    // Extract member_ledger_hash_hex
                    let hash_hex = result_obj
                        .get("member_ledger_hash_hex")
                        .and_then(|v| v.as_str());
                    // Extract cosigner_pubkey
                    let cosigner_str = result_obj.get("cosigner_pubkey").and_then(|v| v.as_str());

                    if let (Some(sig_hex), Some(hash_hex)) = (sig_hex, hash_hex) {
                        let sig_bytes = hex::decode(sig_hex);
                        let hash_bytes = hex::decode(hash_hex);

                        if let (Ok(sig_vec), Ok(hash_vec)) = (sig_bytes, hash_bytes) {
                            if sig_vec.len() == 64 && hash_vec.len() == 32 {
                                let mut sig = [0u8; 64];
                                sig.copy_from_slice(&sig_vec);
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&hash_vec);

                                let cosigner_pubkey = cosigner_str
                                    .and_then(|s| {
                                        use std::str::FromStr;
                                        PublicKey::from_str(s).ok()
                                    })
                                    .unwrap_or(self.node_id); // fallback for old responders

                                let cosign_result = CoSignResult {
                                    cosign_signature: sig,
                                    cosigner_pubkey,
                                    member_ledger_hash: hash,
                                    t1_recv_us: None,
                                    t2_send_us: None,
                                };
                                collector.add(cosign_result);
                                tracing::debug!(
                                    "Co-sign response received: sig + member_hash {}...",
                                    &hash_hex[..8.min(hash_hex.len())]
                                );
                                return;
                            }
                        }
                    }
                    tracing::warn!("Co-sign response missing valid cosign_signature_hex or member_ledger_hash_hex");
                }
            }
            // tx is dropped here if we didn't send, receiver will get an error
            return;
        }

        // Check if this is a response to a pending consent request
        let is_consent_request = {
            let pending = self.pending_consent_requests.lock().unwrap();
            pending.contains_key(&response.request_id)
        };

        if is_consent_request {
            if !response.success {
                tracing::debug!(
                    "Ignoring error consent response for {}: {}",
                    &response.request_id[..16.min(response.request_id.len())],
                    response.error.clone().unwrap_or_default()
                );
                return;
            }

            let consent_sender = {
                let mut pending = self.pending_consent_requests.lock().unwrap();
                pending.remove(&response.request_id)
            };

            if let Some(tx) = consent_sender {
                if let Some(result) = &response.result {
                    let result_obj = if result.is_object() {
                        result.clone()
                    } else if let Some(s) = result.as_str() {
                        serde_json::from_str(s).unwrap_or_default()
                    } else {
                        serde_json::Value::Null
                    };

                    let sig_hex = result_obj.get("consent_signature").and_then(|v| v.as_str());
                    let expires = result_obj
                        .get("membership_expires")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;

                    // Q1 fields: optional, present when member runs the new wire.
                    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
                    let member_response = result_obj
                        .get("member_response")
                        .and_then(|v| v.as_str())
                        .and_then(|s| BASE64.decode(s).ok());
                    let member_signature = result_obj
                        .get("member_signature")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .filter(|v| v.len() == 64)
                        .map(|v| {
                            let mut a = [0u8; 64];
                            a.copy_from_slice(&v);
                            a
                        });

                    if let Some(sig_hex) = sig_hex {
                        if let Ok(sig_vec) = hex::decode(sig_hex) {
                            if sig_vec.len() == 64 {
                                let mut sig = [0u8; 64];
                                sig.copy_from_slice(&sig_vec);
                                let consent_result = ConsentResult {
                                    consent_signature: sig,
                                    membership_expires: expires,
                                    member_response,
                                    member_signature,
                                };
                                let _ = tx.send(consent_result);
                                tracing::info!(
                                    "Consent response received: signature ok, expires block {}",
                                    expires
                                );
                                return;
                            }
                        }
                    }
                    tracing::warn!("Consent response missing valid consent_signature");
                }
            }
        }
    }

    /// Request a co-signature from a quorum member for an update.
    ///
    /// This sends a cosign_update request via Nostr and waits for the response.
    /// The quorum member will validate the update and return their ECDSA signature
    /// over (cosign_data || member_ledger_hash).
    ///
    /// This is a multicast request - it goes to all quorum members subscribed to the
    /// ledger, and the first valid response is used. Each responder auto-detects which
    /// of their ledgers is bound to this one via QuorumJoin.
    ///
    /// # Arguments
    /// * `ledger_id` - The 64-char hex ledger_id hash of the ledger being updated
    /// * `update` - The SignedLedgerUpdate that needs co-signing
    ///
    /// # Returns
    /// A CoSignResult containing the co-signer's signature and the member's ledger hash
    #[tracing::instrument(name = "request_cosign", skip(self, update), fields(ledger = &ledger_id[..16.min(ledger_id.len())], seq = update.sequence_number))]
    #[tracing::instrument(
        name = "request_cosign",
        skip_all,
        fields(
            ledger = %ledger_id,
            seq = update.sequence_number,
            content_hash = %hex::encode(update.content_hash),
        )
    )]
    pub async fn request_cosign(
        &self,
        ledger_id: &str,
        update: &deposits_core::SignedLedgerUpdate,
    ) -> Result<Vec<deposits_core::CosignEntry>, Error> {
        use tokio::time::Duration;

        // Acquire semaphore to serialize cosign requests. Multiple concurrent
        // mini loops compete for shared channels and cause distributed deadlocks
        // when all operators are in batch-await simultaneously. Time spent
        // blocked here is back-pressure — split it out so a slow cosign can be
        // attributed to queueing vs. the actual round-trip.
        let queue_start = std::time::Instant::now();
        let _permit = self
            .cosign_semaphore
            .acquire()
            .await
            .map_err(|_| Error::Protocol("Cosign semaphore closed".to_string()))?;
        let queued = queue_start.elapsed();
        metrics::record_cosign_phase("queue", queued);
        if queued.as_millis() > 50 {
            tracing::debug!(
                queued_ms = queued.as_millis() as u64,
                "cosign permit acquired after queue wait"
            );
        }

        // Compute cosign data
        let cosign_data = update.cosign_data();

        // Create request parameters - responders auto-detect their bound ledger
        let t0_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let mut params = serde_json::json!({
            "sequence_number": update.sequence_number,
            "cosign_data_hex": hex::encode(&cosign_data),
            "content_hash_hex": hex::encode(update.content_hash),
            "message_type": update.message_type,
            "t0_us": t0_us,
        });

        // Piggyback previous updates so quorum members can apply them inline
        // before the freshness check — eliminates "stale by N" failures under
        // load where Nostr latency causes members to fall behind.  Each update
        // is ~200-500 bytes base64, so 100 × 400 ≈ 40 KB — well within the
        // relay's 131 KB max websocket payload.
        {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            use deposits_core::TlvEncode;

            const MAX_PIGGYBACK: usize = 20;

            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(ledger_id) {
                let ledger = arc.read().unwrap();
                let len = ledger.history.len();
                // history[len-1] is the new update; we piggyback the N entries before it
                if len >= 2 {
                    let num = (len - 1).min(MAX_PIGGYBACK);
                    let prev_updates: Vec<String> = ledger.history[len - 1 - num..len - 1]
                        .iter()
                        .map(|u| BASE64.encode(u.tlv_encode()))
                        .collect();
                    params["previous_updates"] = serde_json::json!(prev_updates);
                }
            }
        }

        // Determine cosig threshold per DEP-05 §Lifecycle.
        //
        // Tier-0 active period resolves to strict majority of the
        // active quorum_members (or next_quorum_members for the *first*
        // QuorumBegin, where state is PreQuorum + no active list yet).
        // Past quorum_expiry the helper cascades through minority →
        // single-cosigner → operator-alone for establishment ops, and
        // refuses value-moving ops outright. We translate operator-alone
        // (Tier 3) into `threshold = 0` so the wait loop returns
        // immediately without soliciting any cosignatures.
        let threshold = {
            use deposits_core::cosign_threshold::cosign_requirement;
            use deposits_core::tlv::TlvDecode;
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| {
                    let l = arc.read().unwrap();
                    let op = match deposits_core::LedgerOperation::tlv_decode(&update.message) {
                        Ok(o) => o,
                        // Decode failure — fall back to old default rather
                        // than blow up the request path. Validators will
                        // catch the malformed op separately.
                        Err(_) => return 1,
                    };
                    let req = cosign_requirement(&l.state, &op, update.block_height);
                    if req.operator_alone {
                        0
                    } else if req.required_sigs == 0 {
                        // Pre-quorum non-QuorumBegin or other early-state
                        // updates: ask for one cosig as a sanity check,
                        // matching pre-change behaviour for that branch.
                        1
                    } else {
                        req.required_sigs
                    }
                })
                .unwrap_or(1)
        };

        // Tier 3 (operator-alone, post quorum_expiry + 8064): the
        // helper says zero cosignatures are required. Short-circuit
        // the multicast + wait — no point soliciting signatures we
        // won't honor anyway. The operator's solo signature on the
        // update is what carries the rotation.
        if threshold == 0 {
            tracing::info!(
                "[COSIGN] seq={} Tier-3 operator-alone path: no cosignatures solicited",
                update.sequence_number,
            );
            return Ok(Vec::new());
        }

        let collector = Arc::new(CosignCollector::new(threshold));

        // Send the multicast request to the ledger
        let request_id = self
            .nostr
            .send_ledger_request(ledger_id, "cosign_update", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send co_sign request: {:?}", e)))?;
        self.track_sent_event(&request_id);

        // Store collector in pending requests — handle_ledger_response() accumulates responses.
        {
            let mut pending = self.pending_cosign_requests.lock().unwrap();
            pending.insert(
                request_id.clone(),
                (ledger_id.to_string(), Arc::clone(&collector)),
            );
            metrics::set_pending_cosign_requests(pending.len());
        }

        let cosign_send_time = std::time::Instant::now();
        tracing::debug!(
            "Sent multicast co_sign request {} for seq={} (need {}/{} cosigs)",
            &request_id[..16.min(request_id.len())],
            update.sequence_number,
            threshold,
            threshold, // will show quorum size once we have it
        );

        // Wait until threshold cosignatures collected or timeout.
        //
        // Target: sub-1s in steady state. The 10s default is a safety net for
        // bursts of concurrent cosign rounds (e.g. simultaneous auto_quorum_refresh
        // rotations across many ledgers), where Nostr relay round-trips + the
        // cosigners' inbound wait-for-data shim (see inbound.rs) can stack up
        // beyond 5s under load. Override via `COSIGN_TIMEOUT_MS` env when
        // benchmarking the steady-state path.
        let deadline_ms: u64 = std::env::var("COSIGN_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10000);
        let deadline = Duration::from_millis(deadline_ms);

        tokio::select! {
            _ = collector.notify.notified() => {
                // Threshold reached
            }
            _ = tokio::time::sleep(deadline) => {
                // Timeout — check if we got enough anyway
            }
        }

        // Clean up pending map
        {
            let mut pending = self.pending_cosign_requests.lock().unwrap();
            pending.remove(&request_id);
            metrics::set_pending_cosign_requests(pending.len());
        }

        let results = collector.take_results();
        let cosign_rtt = cosign_send_time.elapsed();
        metrics::record_cosign_phase("rtt", cosign_rtt);

        if results.len() < threshold {
            return Err(Error::Protocol(format!(
                "Cosign timeout: got {}/{} cosigs in {}ms",
                results.len(),
                threshold,
                cosign_rtt.as_millis()
            )));
        }

        tracing::info!(
            "[COSIGN] seq={} collected {}/{} cosigs in {:.0}ms",
            update.sequence_number,
            results.len(),
            threshold,
            cosign_rtt.as_secs_f64() * 1000.0
        );

        // Convert to CosignEntries
        let entries: Vec<deposits_core::CosignEntry> = results
            .into_iter()
            .map(|r| deposits_core::CosignEntry {
                cosigner_pubkey: r.cosigner_pubkey,
                cosign_signature: r.cosign_signature,
                member_ledger_hash: r.member_ledger_hash,
            })
            .collect();

        Ok(entries)
    }

    /// Request consent from a quorum member to join our quorum.
    ///
    /// Sends a `consent_request` to the member's ledger, waits for them to sign
    /// and respond with their consent signature. The member also records a
    /// QuorumJoin on their own ledger as part of handling the request.
    pub(crate) async fn request_consent(
        &self,
        member_ledger_id: &str,
        our_ledger_id: &str,
        proposed_terms: ConsentProposedTerms<'_>,
    ) -> Result<ConsentResult, Error> {
        // Piggyback our ledger history so the member can validate the chain
        // from LedgerOpen and import the ledger before attesting. Without this
        // the member would have to scrape the relay — which races against the
        // operator's own publish path and silently produces "consenting blind"
        // memberships when the import doesn't land in time.
        //
        // Bounded: the whole history of a busy ledger does not fit in one
        // event (108k updates ≈ 100 MB; relays cap messages at a few MB). A
        // relay that drops the oversized event also drops our connection, so
        // every rotation attempt cost us our subscriptions and the rotation
        // never happened (cl-deposits docs/REDTEAM.md finding #2). And a
        // relay that carries it is not enough: nostr-sdk drops any received
        // event over 70 kB (RelayLimits MAX_EVENT_SIZE), so a member on this
        // client never sees it. Past CONSENT_HISTORY_MAX (~1 kB of base64 per
        // update) we send the LedgerOpen-rooted prefix plus `ledger_sequence`;
        // the member's import keeps any longer replica it already holds and
        // gap-fills the rest like any other update gap. cl-deposits sends 40.
        const CONSENT_HISTORY_MAX: usize = 40;
        let (history_b64, tip_seq): (Vec<String>, u64) = {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            use deposits_core::TlvEncode;

            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(our_ledger_id).ok_or_else(|| {
                Error::Protocol(format!("Our ledger not found: {}", our_ledger_id))
            })?;
            let arc = arc.clone();
            drop(ledgers);
            let (tip, in_memory) = {
                let ledger = arc.read().unwrap();
                let tip = ledger.history.last().map(|u| u.sequence_number).unwrap_or(0);
                // In-memory history is capped to the most recent entries
                // (handler::history_retain); only when it still starts at the
                // LedgerOpen can the prefix come from it.
                let rooted = ledger.history.first().map(|u| u.sequence_number) == Some(0);
                let prefix: Option<Vec<_>> = rooted
                    .then(|| ledger.history.iter().take(CONSENT_HISTORY_MAX).cloned().collect());
                (tip, prefix)
            };
            let prefix = match in_memory {
                Some(p) => p,
                None => self
                    .handler
                    .read_persisted_history_prefix(our_ledger_id, CONSENT_HISTORY_MAX as u64)
                    .unwrap_or_default(),
            };
            let sent = prefix.iter().map(|u| BASE64.encode(u.tlv_encode())).collect();
            (sent, tip)
        };

        let mut params = serde_json::json!({
            "operator_pubkey": self.node_id_hex,
            "operator_ledger_id": our_ledger_id,
            "ledger_history": history_b64,
            "ledger_sequence": tip_seq,
            "chosen_ruleset": proposed_terms.chosen_ruleset,
        });
        if let Some(v) = proposed_terms.min_fee_bps {
            params["min_fee_bps"] = v.into();
        }
        if let Some(v) = proposed_terms.min_fee_fixed {
            params["min_fee_fixed"] = v.into();
        }
        if let Some(v) = proposed_terms.max_fee_period {
            params["max_fee_period"] = v.into();
        }
        if let Some(v) = proposed_terms.membership_until {
            params["membership_until"] = v.into();
        }

        let (tx, rx) = tokio::sync::oneshot::channel();

        // Temporarily add member's ledger to our interest set so we receive
        // the response (which is tagged with member_ledger_id).
        self.nostr
            .add_interested_ledger(member_ledger_id.to_string());

        let request_id = self
            .nostr
            .send_ledger_request(member_ledger_id, "consent_request", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send consent request: {:?}", e)))?;
        self.track_sent_event(&request_id);

        {
            let mut pending = self.pending_consent_requests.lock().unwrap();
            pending.insert(request_id.clone(), tx);
        }

        tracing::info!(
            "Sent consent request {} to member ledger {}... (waiting for signature)",
            &request_id[..16.min(request_id.len())],
            &member_ledger_id[..16],
        );

        // Not the cosign budget: granting consent includes the member's own
        // QuorumJoin cosign round (10s on its own) plus importing and
        // validating our ledger, behind whatever its loop is already doing.
        // At 10s a busy member's grant arrived after we had given up, every
        // cycle (a devnet ref↔ref rotation answered at 16s). Per-ledger
        // refresh runs detached (auto_quorum_refresh), so no outer budget
        // cuts this short. cl-deposits waits 60s.
        const CONSENT_TIMEOUT_SECS: u64 = 60;
        let deadline = std::time::Duration::from_secs(CONSENT_TIMEOUT_SECS);

        let result = tokio::select! {
            result = rx => {
                match result {
                    Ok(consent_result) => {
                        tracing::info!("Received consent signature from member");
                        Ok(consent_result)
                    }
                    Err(_) => {
                        Err(Error::Protocol("Consent response channel dropped".to_string()))
                    }
                }
            }
            _ = tokio::time::sleep(deadline) => {
                let mut pending = self.pending_consent_requests.lock().unwrap();
                pending.remove(&request_id);
                Err(Error::Protocol(format!("Consent request timed out after {}s", CONSENT_TIMEOUT_SECS)))
            }
        };

        // Remove member ledger from interest set (we only needed it for the response)
        self.nostr.remove_interested_ledger(member_ledger_id);

        result
    }

    /// Request a co-signature on a deposit offer from quorum members.
    ///
    /// This sends a cosign_offer request via Nostr and waits for the first valid response.
    /// The co-signature proves the operator has valid quorum backing, preventing rogue
    /// former operators from creating valid offers after custody recovery.
    ///
    /// # Arguments
    /// * `ledger_id` - The 64-char hex ledger_id hash
    /// * `offer` - The deposit offer that needs co-signing
    ///
    /// # Returns
    /// An OfferCoSignResult containing the signature, co-signer pubkey, and their ledger hash
    pub async fn request_offer_cosign(
        &self,
        ledger_id: &str,
        offer: &DepositOffer,
    ) -> Result<OfferCoSignResult, Error> {
        use std::str::FromStr;
        use tokio::time::Duration;

        // Create request parameters
        let params = serde_json::json!({
            "offer_id": hex::encode(offer.offer_id),
            "operator_id": offer.operator_id.to_string(),
            "funding_address": offer.funding_address,
            "deadline_block": offer.deadline_block,
        });

        // Create notification receiver BEFORE sending the request so we don't miss
        // any early responses. Each call to create_notification_receiver() creates a
        // new broadcast::Receiver that only sees events from that point forward.
        let mut notification_rx = self.nostr.create_notification_receiver();

        // Send the multicast request to quorum members
        let request_id = self
            .nostr
            .send_ledger_request(ledger_id, "cosign_offer", params)
            .await
            .map_err(|e| {
                Error::Protocol(format!("Failed to send cosign_offer request: {:?}", e))
            })?;
        self.track_sent_event(&request_id);

        tracing::info!(
            "Sent cosign_offer request {} for offer {}... (waiting for first responder)",
            &request_id[..16.min(request_id.len())],
            &hex::encode(&offer.offer_id[..4]),
        );

        // Poll for response - use 3 second timeout for fast operations
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

        loop {
            tokio::select! {
                // Await the next notification from nostr-sdk's background task.
                // By creating notification_rx ONCE (before sending the request) and
                // awaiting recv() here, we properly receive events as they arrive,
                // unlike poll_events() which creates a new empty receiver each call.
                notif = notification_rx.recv() => {
                    // Inline extraction: intercept cosign_offer requests from the
                    // notification stream directly, never putting them in request_rx.
                    let our_x_only = hex::encode(&self.node_id.serialize()[1..]);
                    let mut inline_offer_requests: Vec<crate::nostr::LedgerRequest> = Vec::new();

                    match notif {
                        Ok(notification) => {
                            if let Some(req) = self.nostr.dispatch_or_extract_request(notification, "cosign_offer") {
                                inline_offer_requests.push(req);
                            }
                            loop {
                                match notification_rx.try_recv() {
                                    Ok(n) => {
                                        if let Some(req) = self.nostr.dispatch_or_extract_request(n, "cosign_offer") {
                                            inline_offer_requests.push(req);
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                        tracing::warn!("Offer cosign mini loop notification receiver lagged by {} events", n);
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Offer cosign mini loop notification receiver lagged by {} events", n);
                            loop {
                                match notification_rx.try_recv() {
                                    Ok(n) => {
                                        if let Some(req) = self.nostr.dispatch_or_extract_request(n, "cosign_offer") {
                                            inline_offer_requests.push(req);
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Err(Error::Protocol("Notification channel closed during offer cosign".to_string()));
                        }
                    }

                    // Check for responses
                    while let Some(response) = self.nostr.try_recv_response() {
                        if response.request_id == request_id {
                            if response.success {
                                if let Some(result) = &response.result {
                                    // Parse response fields
                                    let sig_hex = result.get("signature_hex")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing signature_hex".to_string()))?;

                                    let cosigner_pubkey_str = result.get("cosigner_pubkey")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing cosigner_pubkey".to_string()))?;

                                    let member_hash_hex = result.get("member_ledger_hash_hex")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing member_ledger_hash_hex".to_string()))?;

                                    // Decode signature
                                    let sig_bytes = hex::decode(sig_hex)
                                        .map_err(|e| Error::Protocol(format!("Invalid signature hex: {}", e)))?;
                                    if sig_bytes.len() != 64 {
                                        return Err(Error::Protocol("Signature must be 64 bytes".to_string()));
                                    }
                                    let mut signature = [0u8; 64];
                                    signature.copy_from_slice(&sig_bytes);

                                    // Decode cosigner pubkey
                                    let cosigner_pubkey = PublicKey::from_str(cosigner_pubkey_str)
                                        .map_err(|e| Error::Protocol(format!("Invalid cosigner_pubkey: {}", e)))?;

                                    // Decode member ledger hash
                                    let hash_bytes = hex::decode(member_hash_hex)
                                        .map_err(|e| Error::Protocol(format!("Invalid member_ledger_hash_hex: {}", e)))?;
                                    if hash_bytes.len() != 32 {
                                        return Err(Error::Protocol("member_ledger_hash must be 32 bytes".to_string()));
                                    }
                                    let mut member_ledger_hash = [0u8; 32];
                                    member_ledger_hash.copy_from_slice(&hash_bytes);

                                    tracing::info!("Received offer co-signature from {} (member_hash: {}...)",
                                        &cosigner_pubkey_str[..16.min(cosigner_pubkey_str.len())],
                                        &member_hash_hex[..8]);

                                    return Ok(OfferCoSignResult {
                                        signature,
                                        cosigner_pubkey,
                                        member_ledger_hash,
                                    });
                                }
                            } else {
                                let error = response.error.unwrap_or_else(|| "Unknown error".to_string());
                                tracing::warn!("Cosign_offer request failed: {}", error);
                                // Continue waiting for other responses
                            }
                        }
                    }

                    // Process cosign_offer requests extracted inline from notifications.
                    for request in inline_offer_requests {
                        if request.sender != our_x_only
                            && self.is_quorum_member_of_ledger(&request.ledger_id) {
                                // Mark as processed to prevent polling fallback from re-processing
                                self.processed_requests.lock().unwrap().insert(request.event_id.clone());
                                let (success, result, error) = self.process_cosign_offer_request(&request).await;
                                let result_json = result.map(serde_json::Value::String);
                                if let Err(e) = self.nostr.send_ledger_response(
                                    &request.event_id,
                                    &request.ledger_id,
                                    &request.action,
                                    success,
                                    result_json,
                                    error,
                                    request.gift_wrap_sender.as_deref(),
                                ).await {
                                    tracing::debug!("Failed to send cosign_offer response: {}", e);
                                }
                            }
                    }
                }

                // Timeout check
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Protocol("Co-signature required but failed: timeout after 3 seconds".to_string()));
                }
            }
        }
    }

    /// Track a Nostr event sent by this daemon process so we can filter it
    /// when it comes back via the relay broadcast.
    pub(crate) fn track_sent_event(&self, event_id: &str) {
        self.sent_events
            .lock()
            .unwrap()
            .insert(event_id.to_string());
    }

    /// Check if this ledger has an active quorum (set by QuorumBegin).
    ///
    /// After QuorumBegin, co-signatures are required for all updates.
    /// This is derived state — set deterministically by apply_state_changes
    /// and persisted in LedgerState, so it survives history truncation.
    pub(crate) fn is_quorum_active(&self, ledger_id: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            ledger_arc.read().unwrap().state.quorum_state == deposits_core::QuorumState::Active
        } else {
            false
        }
    }
}
