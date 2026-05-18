//! Health request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
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

        // Per-`(ledger, from_seq)` cooldown. The relay fans out a
        // single broadcast to every subscriber, so if multiple peers
        // ask us to resync the same range in a tight window, only
        // the first request does the work; the rest short-circuit
        // with a synthetic success. Without this guard, four peers
        // coming back online at once make the operator re-publish
        // every update in the range four times.
        const RESYNC_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);
        let key = (request.ledger_id.clone(), from_seq);
        {
            let mut last = self.resync_last_broadcast.lock().unwrap();
            if let Some(prev) = last.get(&key) {
                if prev.elapsed() < RESYNC_COOLDOWN {
                    let response = serde_json::json!({
                        "rebroadcast_count": 0,
                        "from_seq": from_seq,
                        "through_seq": from_seq,
                        "total_available": 0,
                        "has_more": false,
                        "deduped": true,
                    });
                    tracing::info!(
                        "Resync for {}/from_seq={} deduped against broadcast {:?} ago",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        from_seq,
                        prev.elapsed()
                    );
                    return (true, Some(response.to_string()), None);
                }
            }
            last.insert(key, std::time::Instant::now());
        }

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
            // Reuse the Nostr `created_at` we recorded the first
            // time this update went over the wire (either when we
            // minted it on commit, or when we observed it in our
            // own inbound feed). With the same created_at the
            // re-broadcast yields the same event id, and relays
            // can dedupe it on event id alone. `None` means we
            // never tracked it — fall through to a fresh now().
            let pinned_ts = self
                .handler
                .event_store
                .lock()
                .unwrap()
                .get(&update.content_hash)
                .and_then(|stored| stored.created_at);
            match self
                .nostr
                .broadcast_ledger_update_at(update, pinned_ts)
                .await
            {
                Ok((_event_id, used_ts)) => {
                    // Record the timestamp if we minted a fresh one
                    // here so the next resync of the same range can
                    // collapse to a no-op at the relay.
                    if pinned_ts.is_none() {
                        self.handler
                            .event_store
                            .lock()
                            .unwrap()
                            .record_created_at(&update.content_hash, used_ts);
                    }
                    rebroadcast_count += 1;
                }
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

}
