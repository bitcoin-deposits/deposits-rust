use super::*;

impl Node {
    /// Start listening for messages
    pub async fn start(&self) -> Result<(), Error> {
        self.nostr.start_listening().await?;

        // Auto-subscribe to ledger requests/disputes for all our ledgers
        // Collect all ledger IDs we care about (owned + joined)
        let mut ledger_ids: Vec<String> = Vec::new();

        let ledgers = self.handler.ledgers.lock().unwrap().clone();
        for (_ledger_id_key, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                ledger_ids.push(ledger.ledger_id_hex());
            }
        }

        // Add joined ledgers
        let joined_ids = self.get_joined_ledger_ids();
        ledger_ids.extend(joined_ids.clone());

        // Seed ALL locally-loaded ledgers (owned + joined) into stale_joined_ledgers
        // so the background gap-fill loop catches up from the relay after restart.
        // This recovers any updates that were deferred (mark_ledger_dirty) but not
        // flushed before the previous shutdown. Safe because reimport_joined_ledger()
        // already checks if fetched data is newer than local tip.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut stale = self.stale_joined_ledgers.lock().unwrap();
            for lid in ledgers.keys() {
                stale.insert(lid.clone());
            }
            if !stale.is_empty() {
                tracing::info!("Seeded {} ledgers for background catch-up", stale.len());
            }
        }

        // Set up per-ledger filters for polling and interested ledger set
        if !ledger_ids.is_empty() {
            self.nostr
                .set_interested_ledgers(ledger_ids.iter().cloned());
            self.nostr.set_request_ledger_filter(ledger_ids.clone());
        }

        // Global subscription was already set up in new(), but ensure it's active
        if let Err(e) = self.nostr.subscribe_global().await {
            tracing::warn!("Failed to subscribe globally: {}", e);
        }

        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Register interest in a specific ledger for event routing.
    /// Call this after opening a new ledger to start watching it.
    /// Global subscription handles all kinds; this just adds to the interest set.
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        self.nostr.add_interested_ledger(ledger_id.to_string());
        Ok(())
    }

    /// Get ledger IDs of ledgers we've joined as a quorum member.
    ///
    /// Uses an incremental scan: on the first call, scans all history. On subsequent
    /// calls, only scans new entries since the last scan. This avoids the O(full_history)
    /// scan that was triggered every 2s reload when history grows during sustained load.
    pub(crate) fn get_joined_ledger_ids(&self) -> Vec<String> {
        // Fast path: check if cache is populated AND history hasn't grown.
        //
        // IMPORTANT: Clone cache data BEFORE acquiring handler.ledgers to avoid
        // ABBA deadlock. The cache-miss path below acquires handler.ledgers first,
        // then joined_ledger_cache. If we held joined_ledger_cache while waiting
        // for handler.ledgers here, a concurrent task in the cache-miss path
        // (holding handler.ledgers, waiting for joined_ledger_cache) would deadlock.
        {
            let (cached_data, cached_versions) = {
                let cache = self.joined_ledger_cache.lock().unwrap();
                let versions = self.joined_ledger_cache_versions.lock().unwrap();
                (cache.clone(), versions.clone())
            };
            // Cache locks released — safe to acquire handler.ledgers

            if let Some(ref cached) = cached_data {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut stale = false;

                if ledgers.len() != cached_versions.len() {
                    stale = true;
                } else {
                    for (lid, arc) in ledgers.iter() {
                        let l = arc.read().unwrap();
                        if l.operator_key() == self.node_id {
                            match cached_versions.get(lid) {
                                Some(&v) if v == l.history.len() => {}
                                _ => {
                                    stale = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if !stale {
                    return cached.clone();
                }
            }
        }

        // Cache miss — incremental scan: only check entries we haven't seen yet.
        // QuorumJoin entries are rare and only appear early in history, so after
        // the first full scan, incremental scans process near-zero new entries.
        let t0 = std::time::Instant::now();
        let mut new_versions = HashMap::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        // Start from previous cached result + scan offsets
        let prev_cache = self.joined_ledger_cache.lock().unwrap().clone();
        let prev_versions = self.joined_ledger_cache_versions.lock().unwrap().clone();
        let mut joined = prev_cache.unwrap_or_default();
        let mut scanned_new = 0usize;

        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                let history_len = ledger.history.len();
                new_versions.insert(ledger_id.clone(), history_len);

                // Only scan entries beyond what we've already scanned.
                // Cap at history_len in case history was truncated.
                let prev_len = prev_versions
                    .get(ledger_id)
                    .copied()
                    .unwrap_or(0)
                    .min(ledger.history.len());
                for update in ledger.history.iter().skip(prev_len) {
                    scanned_new += 1;
                    if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                        continue;
                    }
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::QuorumJoin { ledger_id, .. } = op {
                            if !joined.contains(&ledger_id) {
                                joined.push(ledger_id);
                            }
                        }
                    }
                }
            }
        }
        drop(ledgers);

        let elapsed = t0.elapsed();
        if elapsed.as_millis() > 1 || scanned_new > 100 {
            let total: usize = new_versions.values().sum();
            tracing::info!(
                "[PROFILE] get_joined_ledger_ids: scanned {} new entries ({} total) in {:?}",
                scanned_new,
                total,
                elapsed
            );
        }

        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = Some(joined.clone());
        *self.joined_ledger_cache_versions.lock().unwrap() = new_versions;

        joined
    }

    /// Force-invalidate the joined ledger cache.
    /// Only needed when ledger data changes externally (e.g., discover_new_ledgers).
    pub(crate) fn invalidate_joined_ledger_cache(&self) {
        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = None;
        self.joined_ledger_cache_versions.lock().unwrap().clear();
        // Also invalidate cosign member cache since QuorumJoin mappings may have changed
        self.cosign_member_cache.lock().unwrap().clear();
    }

    /// Auto-import joined ledgers from Nostr so we can validate their updates.
    /// Called from the reload cycle when we discover joined ledger IDs not in our local map.
    pub(crate) async fn auto_import_joined_ledgers(&self, joined_ids: &[String]) {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::validation::LedgerExport;
        use deposits_core::TlvDecode;

        use nostr_sdk::{Filter, Kind};

        for ledger_id in joined_ids {
            // Skip if already in local map
            {
                let ledgers = self.handler.ledgers.lock().unwrap();
                if ledgers.contains_key(ledger_id) {
                    // Mark as imported so we don't check again
                    self.imported_joined_ledgers
                        .lock()
                        .unwrap()
                        .insert(ledger_id.clone());
                    continue;
                }
            }

            // Skip if already attempted import
            {
                let imported = self.imported_joined_ledgers.lock().unwrap();
                if imported.contains(ledger_id) {
                    continue;
                }
            }

            tracing::info!(
                "Auto-importing joined ledger {}...",
                &ledger_id[..16.min(ledger_id.len())]
            );

            // Fetch ledger updates from Nostr
            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(
                    crate::nostr::TAG_LEDGER_ID,
                    [crate::nostr::ledger_tag(ledger_id.as_str())],
                );

            let events = match self
                .nostr
                .fetch_client()
                .fetch_events(vec![filter], None)
                .await
            {
                Ok(events) => events,
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch ledger {} from Nostr: {}",
                        &ledger_id[..16],
                        e
                    );
                    // Mark as attempted so we don't retry every cycle
                    self.imported_joined_ledgers
                        .lock()
                        .unwrap()
                        .insert(ledger_id.clone());
                    continue;
                }
            };

            if events.is_empty() {
                tracing::debug!("No updates found on Nostr for ledger {}", &ledger_id[..16]);
                // Don't mark as imported — operator may not have exported yet
                continue;
            }

            // Decode events into SignedLedgerUpdate
            let mut updates: Vec<deposits_core::SignedLedgerUpdate> = Vec::new();
            for event in events.iter() {
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        updates.push(update);
                    }
                }
            }

            if updates.is_empty() {
                tracing::debug!("No valid updates decoded for ledger {}", &ledger_id[..16]);
                continue;
            }

            // Sort by sequence, dedup exact copies
            updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.content_hash));
            updates.dedup_by(|a, b| {
                a.sequence_number == b.sequence_number
                    && a.operator_id == b.operator_id
                    && a.content_hash == b.content_hash
            });

            // Find LedgerOpen to get metadata
            let ledger_open = updates.iter().find_map(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    if let LedgerOperation::LedgerOpen {
                        operator_id,
                        reserves_id,
                        genesis_block,
                        ..
                    } = op
                    {
                        return Some((operator_id, reserves_id, genesis_block));
                    }
                }
                None
            });

            let Some((operator_id, reserves_id, genesis_block)) = ledger_open else {
                // The operator may not have published its LedgerOpen to this
                // relay yet (Phase 2 vs Phase 3 ordering races, slow relay
                // replication, etc.). Treat this as transient — same posture
                // as `events.is_empty()` above. Marking the ledger imported
                // here would give up forever even after the LedgerOpen later
                // arrives, leaving the member unable to fork the ledger when
                // a dispute fires.
                tracing::debug!(
                    "No LedgerOpen yet for ledger {}, will retry",
                    &ledger_id[..16]
                );
                continue;
            };

            // Build best chain (handle branches: prefer chains with DisputeAcquire, then longest)
            let by_prev: std::collections::HashMap<
                [u8; 32],
                Vec<&deposits_core::SignedLedgerUpdate>,
            > = {
                let mut map = std::collections::HashMap::new();
                for u in &updates {
                    map.entry(u.previous_hash).or_insert_with(Vec::new).push(u);
                }
                map
            };

            // Walk the chain iteratively from genesis. At forks, pick the
            // branch that contains DisputeAcquire (or the longest if tied).
            let best_chain = {
                let mut chain: Vec<&deposits_core::SignedLedgerUpdate> = Vec::new();
                let mut content_hash = [0u8; 32];
                loop {
                    let Some(children) = by_prev.get(&content_hash) else {
                        break;
                    };
                    // Single child (common case): just follow it
                    let next = if children.len() == 1 {
                        children[0]
                    } else {
                        // Fork: peek one step ahead and pick best branch
                        let mut best_child: Option<&deposits_core::SignedLedgerUpdate> = None;
                        let mut best_has_acquire = false;
                        let mut best_depth = 0usize;
                        for &child in children {
                            let has_acquire = LedgerOperation::tlv_decode(&child.message)
                                .map(|op| matches!(op, LedgerOperation::DisputeAcquire { .. }))
                                .unwrap_or(false);
                            // Count chain length from this child (iterative peek)
                            let mut depth = 1usize;
                            let mut h = child.content_hash;
                            while let Some(next_children) = by_prev.get(&h) {
                                if let Some(first) = next_children.first() {
                                    h = first.content_hash;
                                    depth += 1;
                                } else {
                                    break;
                                }
                            }
                            let is_better = best_child.is_none()
                                || (has_acquire && !best_has_acquire)
                                || (has_acquire == best_has_acquire && depth > best_depth);
                            if is_better {
                                best_child = Some(child);
                                best_has_acquire = has_acquire;
                                best_depth = depth;
                            }
                        }
                        match best_child {
                            Some(c) => c,
                            None => break,
                        }
                    };
                    content_hash = next.content_hash;
                    chain.push(next);
                }
                chain
            };
            let filtered: Vec<deposits_core::SignedLedgerUpdate> =
                best_chain.iter().map(|u| (*u).clone()).collect();

            if filtered.is_empty() {
                tracing::warn!("No valid chain found for ledger {}", &ledger_id[..16]);
                self.imported_joined_ledgers
                    .lock()
                    .unwrap()
                    .insert(ledger_id.clone());
                continue;
            }

            // Parse ledger_id bytes
            let ledger_id_bytes: [u8; 32] = match hex::decode(ledger_id) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => {
                    tracing::warn!("Invalid ledger_id hex: {}", &ledger_id[..16]);
                    self.imported_joined_ledgers
                        .lock()
                        .unwrap()
                        .insert(ledger_id.clone());
                    continue;
                }
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            let export = LedgerExport::new(
                ledger_id_bytes,
                genesis_block,
                operator_id,
                reserves_id,
                filtered.clone(),
                block_height,
            );

            match self.handler.import_ledger(export) {
                Ok((_report, _ledger_arc)) => {
                    tracing::info!(
                        "Auto-imported joined ledger {} ({} updates)",
                        &ledger_id[..16],
                        filtered.len()
                    );
                    // Lazy-spawn an actor for this newly-imported ledger
                    // so its inbound stream gets shadowed to `.actor.log`.
                    self.ensure_actor_for(&ledger_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to import ledger {}: {}", &ledger_id[..16], e);
                }
            }

            self.imported_joined_ledgers
                .lock()
                .unwrap()
                .insert(ledger_id.clone());
        }
    }

    /// Re-import a joined ledger from Nostr, replacing any stale local copy.
    ///
    /// Called when `handle_ledger_update` detects a gap between the local
    /// history and an incoming update sequence number.
    pub(crate) async fn reimport_joined_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::validation::LedgerExport;
        use deposits_core::TlvDecode;

        use nostr_sdk::{Filter, Kind, Timestamp};

        // Skip our own ledgers — they're managed via open_ledger, not reimport
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let is_own = ledgers.iter().any(|(k, arc)| {
                k.starts_with(ledger_id) && arc.read().unwrap().operator_key() == self.node_id
            });
            if is_own {
                return Ok(()); // silently skip our own ledger
            }
        }

        let local_tip_seq = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().next_sequence())
                .unwrap_or(0)
        };

        // Paginate forward using Nostr event created_at timestamps.
        // The relay returns newest-first capped by maxFilterLimit per query,
        // so we advance `since` after each page to walk forward through history.
        let mut cursor_ts: u64 = 0;

        let mut all_fetched: Vec<deposits_core::SignedLedgerUpdate> = Vec::new();
        let mut pages = 0u32;
        let max_pages = Self::RELAY_FETCH_MAX_PAGES;

        loop {
            let mut filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(
                    crate::nostr::TAG_LEDGER_ID,
                    [crate::nostr::ledger_tag(ledger_id)],
                )
                .limit(Self::RELAY_FETCH_PAGE_LIMIT);

            if cursor_ts > 0 {
                filter = filter.since(Timestamp::from(cursor_ts));
            }

            let events = self
                .nostr
                .fetch_client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(15)))
                .await
                .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

            if events.is_empty() {
                break;
            }

            let mut page_max_ts = cursor_ts;
            let mut page_count = 0usize;
            for event in events.iter() {
                let event_ts = event.created_at.as_u64();
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        if event_ts > page_max_ts {
                            page_max_ts = event_ts;
                        }
                        all_fetched.push(update);
                        page_count += 1;
                    }
                }
            }

            pages += 1;
            tracing::debug!(
                "reimport_joined_ledger {}...: page {} fetched {} updates (cursor_ts={}, max_ts={})",
                &ledger_id[..16.min(ledger_id.len())], pages, page_count, cursor_ts, page_max_ts,
            );

            // If the max timestamp didn't advance or we got fewer events than
            // our page size, we've reached the end.
            if page_max_ts <= cursor_ts
                || page_count < Self::RELAY_FETCH_MIN_PAGE
                || pages >= max_pages
            {
                break;
            }

            // Advance cursor past the newest event in this page (no overlap buffer
            // needed — dedup below handles any duplicates from boundary events).
            cursor_ts = page_max_ts;
            tokio::task::yield_now().await;
        }

        if all_fetched.is_empty() {
            // If the ledger already exists locally, relay having no events is fine
            // (fast relay expires all events). Not an error — we're already caught up.
            let exists = self.handler.ledgers.lock().unwrap().contains_key(ledger_id);
            if exists {
                tracing::debug!(
                    "Relay has no events for {}... but ledger exists locally — already caught up",
                    &ledger_id[..16.min(ledger_id.len())],
                );
                return Ok(());
            }
            return Err(Error::Protocol("No events on Nostr".into()));
        }

        tracing::info!(
            "reimport_joined_ledger {}...: fetched {} updates in {} pages (local_tip_seq={})",
            &ledger_id[..16.min(ledger_id.len())],
            all_fetched.len(),
            pages,
            local_tip_seq,
        );

        // For existing ledgers (the common case — stale set only contains known
        // ledgers), skip the expensive LedgerOpen search and chain walk. After
        // history truncation, LedgerOpen (seq 0) is gone from memory, so the old
        // genesis-based chain walk always fails. Instead, filter the relay events
        // for updates beyond our tip and append directly.
        let existing = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(ledger_id).cloned()
        };

        let mut need_full_reimport = existing.is_none();

        if let Some(ledger_arc) = existing {
            // --- Fast path: existing ledger, incremental update ---
            let (local_tip_hash, local_next_seq) = {
                let ledger = ledger_arc.read().unwrap();
                (ledger.tail_hash(), ledger.next_sequence())
            };

            // Filter, sort, dedup relay events to those beyond our tip
            let mut new_updates: Vec<_> = all_fetched
                .iter()
                .filter(|u| u.sequence_number >= local_next_seq)
                .cloned()
                .collect();
            new_updates.sort_by_key(|u| u.sequence_number);
            new_updates.dedup_by_key(|u| u.sequence_number);

            if new_updates.is_empty() {
                tracing::debug!(
                    "Ledger {}... already up to date (tip seq={})",
                    &ledger_id[..16.min(ledger_id.len())],
                    local_next_seq,
                );
                return Ok(()); // Already caught up — not an error
            }

            // Verify the first new update chains from our tip
            if new_updates[0].sequence_number == local_next_seq
                && new_updates[0].previous_hash != local_tip_hash
            {
                tracing::warn!(
                    "Chain break on ledger {}... at seq {} — purging and re-importing from genesis",
                    &ledger_id[..16.min(ledger_id.len())],
                    local_next_seq,
                );
                // Remove the corrupted ledger so the slow path can rebuild
                self.handler.ledgers.lock().unwrap().remove(ledger_id);
                self.cosign_member_cache.lock().unwrap().remove(ledger_id);
                self.invalidate_joined_ledger_cache();
                need_full_reimport = true;
            } else {
                match self
                    .handler
                    .apply_updates_to_ledger(ledger_id, new_updates.clone())
                {
                    Ok(applied) => {
                        tracing::info!(
                            "Re-imported joined ledger {} (+{} updates from relay, tip_seq {})",
                            &ledger_id[..16],
                            applied,
                            new_updates.last().map(|u| u.sequence_number).unwrap_or(0),
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to apply relay updates to ledger {}: {}",
                            &ledger_id[..16],
                            e
                        );
                        return Err(Error::Protocol(format!("Apply updates failed: {}", e)));
                    }
                }
            }
        }

        if need_full_reimport {
            // --- Slow path: new ledger, full import from genesis ---
            let mut updates: Vec<deposits_core::SignedLedgerUpdate> = all_fetched;
            updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.content_hash));
            updates.dedup_by(|a, b| {
                a.sequence_number == b.sequence_number
                    && a.operator_id == b.operator_id
                    && a.content_hash == b.content_hash
            });

            let ledger_open = updates.iter().find_map(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    if let LedgerOperation::LedgerOpen {
                        operator_id,
                        reserves_id,
                        genesis_block,
                        ..
                    } = op
                    {
                        return Some((operator_id, reserves_id, genesis_block));
                    }
                }
                None
            });

            let Some((operator_id, reserves_id, genesis_block)) = ledger_open else {
                return Err(Error::Protocol("No LedgerOpen in fetched events".into()));
            };

            // Build best chain from genesis
            let by_prev: std::collections::HashMap<
                [u8; 32],
                Vec<&deposits_core::SignedLedgerUpdate>,
            > = {
                let mut map = std::collections::HashMap::new();
                for u in &updates {
                    map.entry(u.previous_hash).or_insert_with(Vec::new).push(u);
                }
                map
            };

            let best_chain = {
                let mut chain: Vec<&deposits_core::SignedLedgerUpdate> = Vec::new();
                let mut content_hash = [0u8; 32];
                loop {
                    let Some(children) = by_prev.get(&content_hash) else {
                        break;
                    };
                    let next = if children.len() == 1 {
                        children[0]
                    } else {
                        let mut best_child: Option<&deposits_core::SignedLedgerUpdate> = None;
                        let mut best_has_acquire = false;
                        let mut best_depth = 0usize;
                        for &child in children {
                            let has_acquire = LedgerOperation::tlv_decode(&child.message)
                                .map(|op| matches!(op, LedgerOperation::DisputeAcquire { .. }))
                                .unwrap_or(false);
                            let mut depth = 1usize;
                            let mut h = child.content_hash;
                            while let Some(next_children) = by_prev.get(&h) {
                                if let Some(first) = next_children.first() {
                                    h = first.content_hash;
                                    depth += 1;
                                } else {
                                    break;
                                }
                            }
                            let is_better = best_child.is_none()
                                || (has_acquire && !best_has_acquire)
                                || (has_acquire == best_has_acquire && depth > best_depth);
                            if is_better {
                                best_child = Some(child);
                                best_has_acquire = has_acquire;
                                best_depth = depth;
                            }
                        }
                        match best_child {
                            Some(c) => c,
                            None => break,
                        }
                    };
                    content_hash = next.content_hash;
                    chain.push(next);
                }
                chain
            };
            let filtered: Vec<deposits_core::SignedLedgerUpdate> =
                best_chain.iter().map(|u| (*u).clone()).collect();

            if filtered.is_empty() {
                return Err(Error::Protocol("No valid chain found".into()));
            }

            let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
                .map_err(|e| Error::Protocol(format!("Bad hex: {}", e)))
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Ok(arr)
                    } else {
                        Err(Error::Protocol("Wrong length".into()))
                    }
                })?;

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            let export = LedgerExport::new(
                ledger_id_bytes,
                genesis_block,
                operator_id,
                reserves_id,
                filtered.clone(),
                block_height,
            );

            match self.handler.import_ledger(export) {
                Ok(_) => {
                    tracing::info!(
                        "Imported new joined ledger {} ({} updates, tip_seq {} from relay)",
                        &ledger_id[..16],
                        filtered.len(),
                        filtered.last().map(|u| u.sequence_number).unwrap_or(0)
                    );
                    self.ensure_actor_for(&ledger_id);
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to import ledger {}: {}", &ledger_id[..16], e);
                    Err(Error::Protocol(format!("Import failed: {}", e)))
                }
            }
        } else {
            Ok(())
        }
    }

    /// Catch up a joined ledger's history from the event store's validated chain.
    ///
    /// Pure in-memory operation — no relay I/O. Returns the number of events
    /// appended to the ledger history, or 0 if the event store doesn't have
    /// anything beyond the ledger's current history.
    pub(crate) fn catch_up_ledger_from_event_store(&self, ledger_id: &str) -> usize {
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => arc.clone(),
                None => return 0,
            }
        };

        let (ledger_id_bytes, operator_id, local_next_seq) = {
            let ledger = ledger_arc.read().unwrap();
            (
                ledger.state.ledger_id,
                ledger.state.parent_pubkey,
                ledger.next_sequence(),
            )
        };

        let store = self.handler.event_store.lock().unwrap();
        let tip = match store.validated_tip(&ledger_id_bytes, &operator_id) {
            Some(t) => t,
            None => return 0,
        };

        // Event store has nothing beyond what the ledger already has
        if tip < local_next_seq {
            return 0;
        }

        // Collect updates from local_next_seq..=tip
        let mut to_append = Vec::new();
        for seq in local_next_seq..=tip {
            if let Some(stored) = store.get_by_seq(&ledger_id_bytes, &operator_id, seq) {
                if stored.validity == deposits_core::event_store::Validity::Valid {
                    to_append.push(stored.update.clone());
                } else {
                    break; // Chain broken
                }
            } else {
                break; // Gap — can't continue
            }
        }
        drop(store);

        if to_append.is_empty() {
            return 0;
        }

        let _count = to_append.len();
        let mut ledger = ledger_arc.write().unwrap();

        // Re-check after acquiring write lock (another thread may have caught up)
        let next_seq = ledger.next_sequence();
        let mut tip_hash = ledger.tail_hash();
        let mut appended = 0u64;
        for update in to_append {
            if update.sequence_number == next_seq + appended && update.previous_hash == tip_hash {
                // Apply state changes so our state stays current with history
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    let _ = ledger.apply_state_changes(&op);
                }
                tip_hash = update.content_hash;
                ledger.state.sequence = update.sequence_number;
                ledger.state.chain_tip_hash = update.chain_hash();
                ledger.history.push(update);
                appended += 1;
            } else {
                break;
            }
        }

        if appended > 0 {
            // Update state sequence/hash from last appended
            let last_seq = ledger.history.last().map(|u| u.sequence_number);
            let last_hash = ledger.history.last().map(|u| u.chain_hash());
            if let (Some(seq), Some(hash)) = (last_seq, last_hash) {
                ledger.state.sequence = seq;
                ledger.state.chain_tip_hash = hash;
            }

            // Truncate joined ledger history to prevent unbounded memory growth.
            // Owned ledgers are truncated during persist_ledger_to_disk, but joined
            // ledgers are never persisted by this operator, so truncate here.
            const JOINED_HISTORY_RETAIN: usize = 2000;
            let len = ledger.history.len();
            if len > JOINED_HISTORY_RETAIN * 2 {
                ledger.history.drain(..len - JOINED_HISTORY_RETAIN);
            }

            tracing::info!(
                "Caught up ledger {}... from event store: seq {} -> {} (+{} entries)",
                &ledger_id[..16.min(ledger_id.len())],
                next_seq,
                next_seq + appended,
                appended,
            );
        }

        appended as usize
    }

    /// Send a resync request to the operator of a joined ledger asking them
    /// to re-broadcast updates from our local sequence onward. Fire-and-forget.
    pub(crate) async fn send_resync_request_if_needed(&self, ledger_id: &str) {
        // Find the operator pubkey for this ledger
        let operator_pubkey = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    hex::encode(ledger.operator_key().serialize())
                }
                None => return,
            }
        };

        // Get our local sequence
        let from_seq = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => arc.read().unwrap().next_sequence(),
                None => return,
            }
        };

        let params = serde_json::json!({
            "from_seq": from_seq,
            "requester": hex::encode(self.node_id.serialize()),
        });

        match self
            .nostr
            .send_ledger_request(ledger_id, "resync", params)
            .await
        {
            Ok(event_id) => {
                tracing::info!(
                    "Sent resync request for ledger {}... from_seq={} to operator {}...",
                    &ledger_id[..16.min(ledger_id.len())],
                    from_seq,
                    &operator_pubkey[..16.min(operator_pubkey.len())],
                );
                self.sent_events.lock().unwrap().insert(event_id);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to send resync request for ledger {}...: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e,
                );
            }
        }
    }

    /// Run the main event loop.
    /// Takes `&Arc<Self>` to enable per-ledger parallel dispatch via `tokio::spawn`.
    pub async fn run(self: &Arc<Self>) -> Result<(), Error> {
        // Apply-edge dispute driver. When an actor signals
        // `dispute_wakeup` (after observing a fork-branch
        // DisputeArmed), fire `auto_confiscate` immediately instead
        // of waiting for the next `periodic_interval`. The periodic
        // loop still runs `auto_confiscate` on schedule as a safety
        // net for markers missed at startup or retried after the
        // per-request 120s timeout.
        {
            let node = Arc::clone(self);
            let wakeup = self.dispute_wakeup.clone();
            tokio::spawn(async move {
                loop {
                    wakeup.notified().await;
                    tracing::debug!(
                        "dispute_wakeup signaled — running auto_confiscate immediately"
                    );
                    // Hard timeout matches the periodic batch's 10s
                    // budget so a stuck cosig fetch can't hang the
                    // event-driven path.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        node.auto_confiscate(),
                    )
                    .await;
                }
            });
        }

        // Actor outbox drainer. `Node::new` parks the rx because the
        // drainer needs `Arc<Node>` for `request_cosign` /
        // `broadcast_ledger_update` callbacks that don't exist until
        // `Self` is constructed. Pick it up here with
        // `Arc::clone(self)` in scope and route every actor-emitted
        // event to its real handler.
        if let Some(rx) = self.actor_outbox_rx.lock().unwrap().take() {
            let node = Arc::clone(self);
            tokio::spawn(async move {
                use super::ledger_actor::LedgerOutbound;
                let mut rx = rx;
                while let Some((lid, ev)) = rx.recv().await {
                    let lid_short = &lid[..16.min(lid.len())];
                    match ev {
                        LedgerOutbound::MaybeConfiscate { ledger_id } => {
                            tracing::debug!(
                                "actor_outbox[{}…] MaybeConfiscate for {}… — waking dispute pipeline",
                                lid_short,
                                &ledger_id[..16.min(ledger_id.len())]
                            );
                            node.dispute_wakeup.notify_one();
                        }
                        LedgerOutbound::Broadcast { update, reply } => {
                            // Fire-and-forget when reply is None;
                            // sync (await event id) when set. Always
                            // spawn so a slow relay can't stall the
                            // drainer.
                            let node = Arc::clone(&node);
                            let lid = lid.clone();
                            tokio::spawn(async move {
                                let res = node
                                    .nostr
                                    .broadcast_ledger_update(&update)
                                    .await;
                                match (&res, &reply) {
                                    (Ok(_), _) => tracing::trace!(
                                        "actor_outbox[{}…] Broadcast seq={} ok",
                                        &lid[..16.min(lid.len())],
                                        update.sequence_number
                                    ),
                                    (Err(e), _) => tracing::warn!(
                                        "actor_outbox[{}…] Broadcast seq={} failed: {}",
                                        &lid[..16.min(lid.len())],
                                        update.sequence_number,
                                        e
                                    ),
                                }
                                if let Some(reply) = reply {
                                    let _ = reply
                                        .send(res.map_err(|e| e.to_string()));
                                }
                            });
                        }
                        LedgerOutbound::RequestCosig { update, reply, .. } => {
                            // Cosig collection talks to peers over
                            // Nostr; spawn so the drainer doesn't
                            // serialize on a multi-second round-trip.
                            let node = Arc::clone(&node);
                            let lid = lid.clone();
                            tokio::spawn(async move {
                                let result = node
                                    .request_cosign(&lid, &update)
                                    .await
                                    .map_err(|e| e.to_string());
                                if let Err(ref e) = result {
                                    tracing::warn!(
                                        "actor_outbox[{}…] RequestCosig seq={} failed: {}",
                                        &lid[..16.min(lid.len())],
                                        update.sequence_number,
                                        e
                                    );
                                }
                                let _ = reply.send(result);
                            });
                        }
                    }
                }
                tracing::info!("actor_outbox drainer: all actors gone, exiting");
            });
        }

        // Track last ledger reload time
        let mut last_reload = tokio::time::Instant::now();
        let reload_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(2)
        } else {
            tokio::time::Duration::from_secs(5)
        };

        // Track last request poll time (fallback for missed subscription events)
        let mut last_poll = tokio::time::Instant::now();
        let poll_interval = tokio::time::Duration::from_secs(30); // Safety net only — subscriptions handle real-time delivery

        // Track last periodic tasks time (wallet sync, auto-complete deposits, etc.)
        let mut last_periodic = tokio::time::Instant::now();
        let periodic_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(5)
        } else {
            tokio::time::Duration::from_secs(60)
        };

        // Full wallet sync is expensive (~40 HTTP requests to Electrs).
        // Run it much less frequently than the periodic tasks.
        let mut last_wallet_sync = tokio::time::Instant::now();
        let wallet_sync_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(30)
        } else {
            tokio::time::Duration::from_secs(60)
        };

        if self.fast_poll {
            tracing::info!(
                "Fast poll mode enabled: periodic=5s, wallet_sync=30s, poll=30s, reload=2s"
            );
        }

        // Adaptive timeout: short when busy (more requests likely coming),
        // longer when idle (save CPU). Starts idle.
        let mut had_requests_last_iteration = false;

        let mut loop_iteration: u64 = 0;
        loop {
            let loop_start = std::time::Instant::now();
            loop_iteration += 1;

            // Watchdog: log every 100th iteration so we can see if the loop is running
            if loop_iteration % 100 == 0 {
                tracing::debug!("run loop iteration {}", loop_iteration);
            }

            // Full wallet sync (every 30s fast / 60s normal) — expensive, ~40 HTTP requests
            if last_wallet_sync.elapsed() >= wallet_sync_interval {
                if let Err(e) = self.sync_wallet() {
                    tracing::warn!("Full wallet sync failed: {}", e);
                }
                last_wallet_sync = tokio::time::Instant::now();
            }

            // Periodic tasks (every 5s fast / 60s normal)
            if last_periodic.elapsed() >= periodic_interval {
                let periodic_start = std::time::Instant::now();
                tracing::debug!("[CANARY] entering periodic section (v2-timeout-all)");
                // Lightweight block height sync (2 HTTP requests)
                if let Err(e) = self.sync_block_height() {
                    tracing::warn!("Block height sync failed: {}", e);
                }

                // Spawn cosign-heavy periodic tasks as background work so the main
                // loop stays free to pump events and route cosign responses.
                // These tasks call sign_and_broadcast → request_cosign, which needs
                // the main loop to be running to route responses via process_events.
                {
                    let node = Arc::clone(self);
                    tokio::spawn(async move {
                        macro_rules! timed_periodic {
                            ($name:expr, $call:expr) => {
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    $call,
                                )
                                .await
                                {
                                    Ok(()) => {}
                                    Err(_) => tracing::error!(
                                        "Periodic task '{}' timed out after 10s",
                                        $name
                                    ),
                                }
                            };
                        }
                        timed_periodic!("auto_complete_deposits", node.auto_complete_deposits());
                        timed_periodic!(
                            "auto_credit_received_payments",
                            node.auto_credit_received_payments()
                        );
                        timed_periodic!(
                            "auto_complete_outbound_payments",
                            node.auto_complete_outbound_payments()
                        );
                        timed_periodic!(
                            "auto_complete_withdrawals",
                            node.auto_complete_withdrawals()
                        );
                        timed_periodic!("auto_collect_fees", node.auto_collect_fees());
                        timed_periodic!("auto_timeout_transfers", node.auto_timeout_transfers());

                        // Auto-expire old deposit offers
                        if let Ok(expired) = node.check_expired_offers() {
                            if !expired.is_empty() {
                                tracing::info!("Expired {} deposit offers", expired.len());
                            }
                        }

                        // Dispute-related periodic tasks
                        timed_periodic!(
                            "auto_lottery_claim_or_yield",
                            node.auto_lottery_claim_or_yield()
                        );
                        timed_periodic!("auto_confiscate", node.auto_confiscate());
                        timed_periodic!(
                            "auto_reveal_on_confiscation",
                            node.auto_reveal_on_confiscation()
                        );
                        timed_periodic!("auto_post_win_cleanup", node.auto_post_win_cleanup());

                        // Reload allowlist (non-async, fast)
                        node.reload_allowlist();

                        // Publish price oracle (~every periodic cycle)
                        node.publish_price_oracle().await;

                        // Re-mirror advertisements to durable relay (handles relay restarts)
                        node.nostr.remirror_advertisements().await;
                    });
                }

                // Drain and log events
                let events = self.handler.drain_events();
                for event in events {
                    tracing::info!("Protocol event: {:?}", event);
                }

                // Two-generation cleanup for processed_requests.
                // Swap current → prev each period. Lookups check both generations,
                // so no entry is lost within the last period. This prevents
                // reprocessing of transfer_lock/transfer_complete (one-time nonces)
                // while capping memory at ~2 periods of entries.
                {
                    let mut current = self.processed_requests.lock().unwrap();
                    let mut prev = self.processed_requests_prev.lock().unwrap();
                    metrics::set_processed_requests_current(current.len());
                    metrics::set_processed_requests_prev(prev.len());
                    if current.len() > 1_000 {
                        let cur_len = current.len();
                        let prev_len = prev.len();
                        *prev = std::mem::take(&mut *current);
                        tracing::debug!(
                            "Rotated processed_requests: current={} -> prev (dropped {} old)",
                            cur_len,
                            prev_len
                        );
                    }
                }

                // Two-generation cleanup for sent_events (same pattern as processed_requests).
                // Prevents the atomic clear() bug where wiping all entries at once creates
                // a window for reprocessing our own broadcast events.
                {
                    let mut current = self.sent_events.lock().unwrap();
                    let mut prev = self.sent_events_prev.lock().unwrap();
                    if current.len() > 1_000 {
                        *prev = std::mem::take(&mut *current);
                    }
                }

                // Rotate notification-level dedup set
                self.nostr.rotate_seen_events();

                // Truncate joined ledger histories to prevent unbounded memory growth.
                // Owned ledgers are truncated during persist_ledger_to_disk compaction,
                // but joined ledgers accumulate history from Nostr updates forever.
                if let Ok(ledgers) = self.handler.ledgers.try_lock() {
                    const JOINED_HISTORY_RETAIN: usize = 2000;
                    for (lid, arc) in ledgers.iter() {
                        let mut ledger = arc.write().unwrap();
                        let len = ledger.history.len();
                        if len > JOINED_HISTORY_RETAIN * 2 {
                            let before = len;
                            ledger.history.drain(..len - JOINED_HISTORY_RETAIN);
                            tracing::debug!(
                                "Truncated history for {}: {} -> {} entries",
                                &lid[..16.min(lid.len())],
                                before,
                                ledger.history.len()
                            );
                        }
                    }
                }

                metrics::record_run_loop_phase("periodic", periodic_start.elapsed());
                last_periodic = tokio::time::Instant::now();
            }

            // Discover new/updated ledger files and refresh quorum membership cache
            if last_reload.elapsed() >= reload_interval {
                tracing::debug!("[CANARY] entering reload section (v2-timeout-all)");
                // Pre-check: skip entire reload if ledgers lock is contended
                // (orphaned JoinSet tasks may still hold it after abort_all+drain timeout).
                if self.handler.ledgers.try_lock().is_err() {
                    tracing::warn!("reload section: ledgers lock contended, skipping this cycle");
                    last_reload = tokio::time::Instant::now();
                } else {
                    let reload_start = std::time::Instant::now();
                    let discovered = self.handler.discover_new_ledgers();
                    if discovered > 0 {
                        // Force-invalidate: external process changed ledger files
                        self.invalidate_joined_ledger_cache();
                    }
                    // Otherwise, get_joined_ledger_ids() self-validates via version check

                    // Single pass over ledgers: collect IDs, emit metrics, gather event store keys.
                    // This avoids two separate iterations and eliminates the nested
                    // event_store + ledgers lock that risked deadlock with catch_up paths.
                    let mut all_ledger_ids = self.get_joined_ledger_ids();
                    let mut owned_ids = Vec::new();
                    let mut tip_queries: Vec<(String, [u8; 32], bitcoin::secp256k1::PublicKey)> =
                        Vec::new();
                    {
                        let ledgers = match self.handler.ledgers.try_lock() {
                            Ok(l) => l,
                            Err(_) => {
                                tracing::warn!(
                                    "reload section: ledgers lock contended, skipping this cycle"
                                );
                                last_reload = tokio::time::Instant::now();
                                continue;
                            }
                        };
                        metrics::set_ledger_count(ledgers.len());
                        let mut total_balance_sats: u64 = 0;
                        let mut total_history_bytes: u64 = 0;
                        for (ledger_id, ledger_arc) in ledgers.iter() {
                            let ledger = ledger_arc.read().unwrap();
                            if ledger.operator_key() == self.node_id {
                                all_ledger_ids.push(ledger_id.clone());
                                owned_ids.push(ledger.ledger_id_hex());
                            }
                            let hist_len = ledger.history.len();
                            metrics::set_ledger_history_length(ledger_id, hist_len);
                            // ~570 bytes per entry (370 struct + ~200 avg message Vec)
                            total_history_bytes += hist_len as u64 * 570;
                            // Emit per-ledger and per-deposit balance metrics
                            let mut ledger_balance_sats: u64 = 0;
                            for (dep_id_bytes, deposit) in &ledger.state.deposits {
                                let balance_sats = deposit.balance / 1000;
                                ledger_balance_sats += balance_sats;
                                let dep_id = hex::encode(dep_id_bytes);
                                metrics::set_deposit_balance_sats(&dep_id, balance_sats);
                            }
                            metrics::set_ledger_deposit_balance_sats(
                                ledger_id,
                                ledger_balance_sats,
                            );
                            total_balance_sats += ledger_balance_sats;
                            tip_queries.push((
                                ledger_id.clone(),
                                ledger.state.ledger_id,
                                ledger.state.parent_pubkey,
                            ));
                        }
                        metrics::set_total_deposit_balance_sats(total_balance_sats);
                        metrics::set_history_memory_estimate_bytes(total_history_bytes);
                    }

                    // Emit event store validated tips — separate lock, no nesting
                    {
                        let store = self.handler.event_store.lock().unwrap();
                        for (ledger_id, ledger_id_bytes, parent_pubkey) in &tip_queries {
                            if let Some(tip) = store.validated_tip(ledger_id_bytes, parent_pubkey) {
                                metrics::set_event_store_validated_tip(ledger_id, tip);
                            }
                        }
                    }

                    // Update interested ledgers + poll filter
                    self.nostr
                        .set_interested_ledgers(all_ledger_ids.iter().cloned());
                    self.nostr.set_request_ledger_filter(all_ledger_ids.clone());

                    // Auto-import joined ledgers from Nostr (so we can validate their updates)
                    let joined_ids = self.get_joined_ledger_ids();
                    if !joined_ids.is_empty() {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            self.auto_import_joined_ledgers(&joined_ids),
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(_) => {
                                tracing::error!("auto_import_joined_ledgers timed out after 10s")
                            }
                        }
                    }

                    // Subscribe with compacted global filters (4 filters instead of 36+ per-ledger).
                    // Per-ledger filtering happens in-process via interested_ledgers.
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.nostr.subscribe_global(),
                    )
                    .await
                    {
                        Ok(Err(e)) => tracing::debug!("Global subscribe failed: {}", e),
                        Err(_) => tracing::error!("subscribe_global timed out after 5s"),
                        _ => {}
                    }

                    // Background gap-fill for stale joined ledgers.
                    // Try event store first (free, in-memory), then fall back to relay fetch
                    // (one per cycle, 30s cooldown per ledger) for post-restart recovery.
                    {
                        let stale_ids: Vec<String> = {
                            let mut stale = self.stale_joined_ledgers.lock().unwrap();
                            stale.drain().collect()
                        };

                        let mut relay_fetched_this_cycle = false;
                        let relay_cooldown = Self::RELAY_FETCH_COOLDOWN;

                        for stale_id in &stale_ids {
                            // Try event store first (free, in-memory)
                            let caught_up = self.catch_up_ledger_from_event_store(stale_id);
                            if caught_up > 0 {
                                tracing::debug!(
                                    "Background gap-fill: ledger {}... +{} events from event store",
                                    &stale_id[..16.min(stale_id.len())],
                                    caught_up,
                                );
                                metrics::record_gap_fill("from_store");
                                continue; // Resolved — don't re-queue
                            }

                            // Event store empty (typical after restart). Try relay fetch
                            // — one per cycle to avoid blocking the run loop.
                            if !relay_fetched_this_cycle {
                                let should_fetch = {
                                    let times = self.last_relay_fetch_times.lock().unwrap();
                                    match times.get(stale_id) {
                                        Some(last) => last.elapsed() >= relay_cooldown,
                                        None => true,
                                    }
                                };

                                if should_fetch {
                                    relay_fetched_this_cycle = true;
                                    self.last_relay_fetch_times
                                        .lock()
                                        .unwrap()
                                        .insert(stale_id.clone(), std::time::Instant::now());

                                    let local_seq = {
                                        let ledgers = self.handler.ledgers.lock().unwrap();
                                        ledgers
                                            .get(stale_id)
                                            .map(|arc| arc.read().unwrap().next_sequence())
                                            .unwrap_or(0)
                                    };

                                    // Skip gap-fill if cosign requests are pending — the relay fetch
                                    // blocks the run loop and prevents cosign responses from being processed.
                                    if !self.pending_cosign_requests.lock().unwrap().is_empty() {
                                        tracing::debug!(
                                            "Skipping gap-fill for {}... (cosign pending)",
                                            &stale_id[..16.min(stale_id.len())]
                                        );
                                        self.stale_joined_ledgers
                                            .lock()
                                            .unwrap()
                                            .insert(stale_id.clone());
                                        continue;
                                    }

                                    tracing::debug!(
                                    "Background gap-fill: fetching ledger {}... from relay (local_seq={})",
                                    &stale_id[..16.min(stale_id.len())], local_seq,
                                );

                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(10),
                                        self.reimport_joined_ledger(stale_id),
                                    )
                                    .await
                                    {
                                        Err(_) => {
                                            tracing::error!(
                                                "reimport_joined_ledger timed out for {}...",
                                                &stale_id[..16.min(stale_id.len())]
                                            );
                                            // Re-queue for next cycle
                                            self.stale_joined_ledgers
                                                .lock()
                                                .unwrap()
                                                .insert(stale_id.clone());
                                        }
                                        Ok(Ok(())) => {
                                            let new_seq = {
                                                let ledgers = self.handler.ledgers.lock().unwrap();
                                                ledgers
                                                    .get(stale_id)
                                                    .map(|arc| arc.read().unwrap().next_sequence())
                                                    .unwrap_or(0)
                                            };
                                            tracing::debug!(
                                            "Background gap-fill: relay fetch succeeded for {}... (seq {} -> {})",
                                            &stale_id[..16.min(stale_id.len())], local_seq, new_seq,
                                        );
                                            if new_seq > local_seq {
                                                metrics::record_gap_fill("from_relay");
                                                // Persist the updated ledger
                                                self.dirty_ledgers
                                                    .lock()
                                                    .unwrap()
                                                    .insert(stale_id.clone());
                                                continue; // Resolved — don't re-queue
                                            }
                                            // Relay had no new events — ask operator to re-broadcast.
                                            // Only resync every 5 minutes to avoid spamming.
                                            let should_resync = {
                                                let cooldown = std::time::Duration::from_secs(300);
                                                let times =
                                                    self.last_relay_fetch_times.lock().unwrap();
                                                let last = times.get(stale_id).copied().unwrap_or(
                                                    std::time::Instant::now() - cooldown,
                                                );
                                                last.elapsed() >= cooldown
                                            };
                                            if should_resync {
                                                tracing::info!(
                                                "Background gap-fill: relay had no new events for {}..., requesting resync",
                                                &stale_id[..16.min(stale_id.len())],
                                            );
                                                metrics::record_gap_fill("relay_empty");
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(5),
                                                    self.send_resync_request_if_needed(stale_id),
                                                )
                                                .await;
                                            } else {
                                                tracing::debug!(
                                                "Background gap-fill: relay empty for {}..., resync on cooldown",
                                                &stale_id[..16.min(stale_id.len())],
                                            );
                                            }
                                            // Local tip == relay tip. Drop from the stale set;
                                            // the inbound path (inbound.rs) will re-mark it
                                            // stale if a future event arrives with a sequence
                                            // gap. Without this, every joined ledger gets
                                            // re-fetched every RELAY_FETCH_COOLDOWN forever.
                                            continue;
                                        }
                                        Ok(Err(e)) => {
                                            let err_str = format!("{}", e);
                                            // Chain break = unbridgeable gap (operator history truncated).
                                            // Don't resync — it will just repeat the same failure.
                                            if err_str.contains("wrong previous_hash")
                                                || err_str.contains("Chain break")
                                            {
                                                tracing::info!(
                                                "Background gap-fill: chain break for {}... — dropping from stale queue (gap is unbridgeable)",
                                                &stale_id[..16.min(stale_id.len())],
                                            );
                                                metrics::record_gap_fill("chain_break");
                                                continue; // Don't re-queue
                                            }
                                            tracing::warn!(
                                            "Background gap-fill: relay fetch failed for {}...: {}",
                                            &stale_id[..16.min(stale_id.len())], e,
                                        );
                                            metrics::record_gap_fill("relay_failed");
                                            // Only resync every 5 minutes
                                            let should_resync = {
                                                let cooldown = std::time::Duration::from_secs(300);
                                                let times =
                                                    self.last_relay_fetch_times.lock().unwrap();
                                                let last = times.get(stale_id).copied().unwrap_or(
                                                    std::time::Instant::now() - cooldown,
                                                );
                                                last.elapsed() >= cooldown
                                            };
                                            if should_resync {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(5),
                                                    self.send_resync_request_if_needed(stale_id),
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                }
                            }

                            // Re-queue for next cycle. Reaches here when:
                            //   - relay fetch was deferred (cooldown active or another
                            //     ledger took this cycle's single fetch slot)
                            //   - relay fetch failed with a non-chain-break error
                            // The "fetch succeeded but at-tip" and "fetch succeeded with
                            // new events" cases continue earlier; chain breaks and
                            // cosign-pending defers handle their own re-queue / drop.
                            self.stale_joined_ledgers
                                .lock()
                                .unwrap()
                                .insert(stale_id.clone());
                        }

                        let remaining = self.stale_joined_ledgers.lock().unwrap().len();
                        metrics::set_stale_joined_ledgers(remaining);
                    }

                    // Emit event store stats
                    {
                        let store = self.handler.event_store.lock().unwrap();
                        metrics::set_event_store_total(store.len());
                        metrics::set_event_store_unknown(store.unknown_count());
                        metrics::set_event_store_by_parent_size(store.by_parent_len());
                        metrics::set_event_store_evictions(store.evicted_total());
                    }

                    // Emit process-level metrics (CPU, memory, I/O) + per-thread CPU
                    metrics::emit_process_metrics();
                    metrics::emit_thread_cpu_metrics();

                    // Check for paid Lightning invoices — spawn as a task so it doesn't
                    // block the main loop (credit_deposit → sign_and_broadcast → request_cosign
                    // needs the main loop to pump events for response delivery).
                    if !self.pending_invoices.lock().unwrap().is_empty() {
                        let node = Arc::clone(self);
                        tokio::spawn(async move {
                            node.auto_credit_received_payments().await;
                        });
                    }

                    metrics::record_run_loop_phase("reload", reload_start.elapsed());
                    last_reload = tokio::time::Instant::now();
                } // else (reload body)
            }

            // Poll for recent requests — safety net for missed subscription events.
            // Uses per-ledger parallel dispatch (same as drain_requests).
            if last_poll.elapsed() >= poll_interval {
                let poll_start = std::time::Instant::now();
                let mut poll_processed = 0usize;
                if let Ok(requests) = self.nostr.fetch_recent_requests(7).await {
                    let mut poll_by_ledger: std::collections::HashMap<
                        String,
                        Vec<crate::nostr::LedgerRequest>,
                    > = std::collections::HashMap::new();
                    for request in requests {
                        let already_processed = {
                            let processed = self.processed_requests.lock().unwrap();
                            if processed.contains(&request.event_id) {
                                true
                            } else {
                                self.processed_requests_prev
                                    .lock()
                                    .unwrap()
                                    .contains(&request.event_id)
                            }
                        };
                        if !already_processed {
                            tracing::debug!(
                                "Request via polling: action={}, event={}...",
                                request.action,
                                &request.event_id[..16.min(request.event_id.len())]
                            );
                            self.processed_requests
                                .lock()
                                .unwrap()
                                .insert(request.event_id.clone());
                            poll_by_ledger
                                .entry(request.ledger_id.clone())
                                .or_default()
                                .push(request);
                            poll_processed += 1;
                        }
                    }
                    if !poll_by_ledger.is_empty() {
                        // Dispatch poll requests to workers (non-blocking)
                        for (_lid, reqs) in poll_by_ledger {
                            for req in reqs {
                                if req.action == "cosign_update"
                                    || req.action == "cosign_offer"
                                    || req.action == "cosign_invoice"
                                {
                                    // Dispatch to cosign worker
                                    let lid = req.ledger_id.clone();
                                    let mut workers = self.cosign_workers.lock().unwrap();
                                    let tx = workers.entry(lid.clone()).or_insert_with(|| {
                                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<
                                            crate::nostr::LedgerRequest,
                                        >(
                                        );
                                        let node = Arc::clone(self);
                                        let lid_for_task = lid.clone();
                                        tokio::spawn(async move {
                                            while let Some(r) = rx.recv().await {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(3),
                                                    node.handle_ledger_request(r),
                                                )
                                                .await;
                                            }
                                            tracing::info!(
                                                "Cosign worker (poll) exiting for {}...",
                                                &lid_for_task[..16.min(lid_for_task.len())]
                                            );
                                        });
                                        tx
                                    });
                                    let _ = tx.send(req);
                                } else {
                                    // Dispatch to ledger worker
                                    let lid = req.ledger_id.clone();
                                    let mut workers = self.ledger_workers.lock().unwrap();
                                    let tx = workers.entry(lid.clone()).or_insert_with(|| {
                                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<
                                            crate::nostr::LedgerRequest,
                                        >(
                                        );
                                        let node = Arc::clone(self);
                                        let lid_for_task = lid.clone();
                                        tokio::spawn(async move {
                                            while let Some(r) = rx.recv().await {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(5),
                                                    node.handle_ledger_request(r),
                                                )
                                                .await;
                                            }
                                            tracing::info!(
                                                "Per-ledger worker (poll) exiting for {}...",
                                                &lid_for_task[..16.min(lid_for_task.len())]
                                            );
                                        });
                                        tx
                                    });
                                    let _ = tx.send(req);
                                }
                            }
                        }
                    }
                }
                if poll_processed > 0 {
                    had_requests_last_iteration = true;
                }
                self.flush_dirty_ledgers();
                metrics::record_run_loop_phase("polling", poll_start.elapsed());
                last_poll = tokio::time::Instant::now();
            }

            // Process subscription notifications — adaptive timeout:
            // 1ms when busy (previous iteration processed requests, more likely coming)
            // 10ms when idle (responsive to cosign requests), 1ms when active
            let events_timeout_ms: u64 = if had_requests_last_iteration { 1 } else { 10 };
            metrics::record_events_timeout_ms(events_timeout_ms);
            let process_events_start = std::time::Instant::now();
            let _ = self
                .nostr
                .process_events_with_timeout(events_timeout_ms)
                .await;
            metrics::record_run_loop_phase("process_events", process_events_start.elapsed());

            // Handle P2P messages
            while let Some(inbound) = self.nostr.try_recv() {
                self.handle_inbound(inbound);
            }

            // Handle ledger requests — persistent per-ledger worker dispatch.
            //
            // Each ledger gets a dedicated mpsc channel and a persistent tokio task.
            // The main loop routes requests to channels. Workers process requests
            // one at a time with zero spawn/reap overhead. Cosign requests are
            // still processed inline (fast, time-critical).
            let subscription_batch_size = {
                let drain_start = std::time::Instant::now();

                // Drain requests from Nostr
                let drain_budget = std::time::Duration::from_millis(5);
                let mut total_drained = 0usize;
                let mut cosign_count = 0usize;

                while let Some(request) = self.nostr.try_recv_request() {
                    let already_processed = {
                        let processed = self.processed_requests.lock().unwrap();
                        if processed.contains(&request.event_id) {
                            true
                        } else {
                            self.processed_requests_prev
                                .lock()
                                .unwrap()
                                .contains(&request.event_id)
                        }
                    };
                    if already_processed {
                        if drain_start.elapsed() >= drain_budget {
                            break;
                        }
                        continue;
                    }

                    self.processed_requests
                        .lock()
                        .unwrap()
                        .insert(request.event_id.clone());
                    tracing::info!(
                        "RECV request: action={}, ledger={}..., sender={}..., age={:.0}ms",
                        request.action,
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        &request.sender[..12.min(request.sender.len())],
                        {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            (now.saturating_sub(request.timestamp) as f64) * 1000.0
                        },
                    );

                    // Cosign requests: dispatch to per-ledger cosign worker (non-blocking)
                    // These are requests from PARTNERS asking US to co-sign their updates.
                    // Must not block main loop — main loop needs to pump process_events +
                    // drain_responses so our OWN outbound cosign responses get routed.
                    if request.action == "cosign_update"
                        || request.action == "cosign_offer"
                        || request.action == "cosign_invoice"
                    {
                        let lid = request.ledger_id.clone();
                        let mut workers = self.cosign_workers.lock().unwrap();
                        let tx = workers.entry(lid.clone()).or_insert_with(|| {
                            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<
                                crate::nostr::LedgerRequest,
                            >();
                            let node = Arc::clone(self);
                            let lid_for_task = lid.clone();
                            tokio::spawn(async move {
                                while let Some(req) = rx.recv().await {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(3),
                                        node.handle_ledger_request(req),
                                    )
                                    .await;
                                }
                                tracing::info!(
                                    "Cosign worker exiting for {}...",
                                    &lid_for_task[..16.min(lid_for_task.len())]
                                );
                            });
                            tx
                        });
                        let _ = tx.send(request);
                        cosign_count += 1;
                    } else {
                        // Route to persistent per-ledger worker
                        let lid = request.ledger_id.clone();
                        let mut workers = self.ledger_workers.lock().unwrap();
                        let tx = workers.entry(lid.clone()).or_insert_with(|| {
                            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::nostr::LedgerRequest>();
                            let node = Arc::clone(self);
                            let lid_for_task = lid.clone();
                            tokio::spawn(async move {
                                while let Some(req) = rx.recv().await {
                                    let action = req.action.clone();
                                    let event_id = req.event_id.clone();
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(30),
                                        node.handle_ledger_request(req),
                                    ).await {
                                        Ok(()) => {},
                                        Err(_) => {
                                            tracing::warn!(
                                                "Request timed out after 30s: ledger={}... action={}, event={}...",
                                                &lid_for_task[..16.min(lid_for_task.len())],
                                                action, &event_id[..16.min(event_id.len())]
                                            );
                                        }
                                    }
                                }
                                tracing::info!("Per-ledger worker exiting for {}...", &lid_for_task[..16.min(lid_for_task.len())]);
                            });
                            tx
                        });
                        if let Err(e) = tx.send(request) {
                            tracing::warn!(
                                "Per-ledger worker channel closed for {}...: {}",
                                &lid[..16.min(lid.len())],
                                e
                            );
                            workers.remove(&lid);
                        }
                        total_drained += 1;
                    }

                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                }

                if cosign_count > 0 {
                    tracing::trace!("Processed {} cosign requests (serial)", cosign_count);
                }
                if total_drained > 0 {
                    metrics::record_request_drain_batch_size(total_drained);
                }
                metrics::record_run_loop_phase("drain_requests", drain_start.elapsed());
                total_drained
            };

            // Flush any ledgers modified during request processing

            let flush_start = std::time::Instant::now();
            self.flush_dirty_ledgers();
            metrics::record_run_loop_phase("flush", flush_start.elapsed());

            // Background compaction: check if any ledgers need compaction and spawn
            // a blocking task so the run loop stays free to pump events and cosigns.
            {
                let needs_compaction = self.handler.ledgers_needing_compaction();
                if !needs_compaction.is_empty() {
                    let handler = self.handler.clone();
                    tokio::task::spawn_blocking(move || {
                        for ledger_id in &needs_compaction {
                            if let Err(e) = handler.compact_ledger(ledger_id) {
                                tracing::warn!(
                                    "Background compaction failed for {}: {}",
                                    &ledger_id[..16.min(ledger_id.len())],
                                    e
                                );
                            }
                        }
                    });
                }
            }

            // Handle disputes
            {
                let phase_start = std::time::Instant::now();
                while let Some(dispute) = self.nostr.try_recv_dispute() {
                    tracing::info!(
                        "RECV dispute: ledger={}..., reason={}, from={}...",
                        &dispute.ledger_id[..16.min(dispute.ledger_id.len())],
                        dispute.reason,
                        &dispute.disputer_pubkey[..12.min(dispute.disputer_pubkey.len())]
                    );
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.handle_dispute(dispute),
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::error!("handle_dispute timed out after 5s");
                            break;
                        }
                    }
                }
                metrics::record_run_loop_phase("drain_disputes", phase_start.elapsed());
            }

            // Handle fraud proofs
            {
                let phase_start = std::time::Instant::now();
                while let Some(fp) = self.nostr.try_recv_fraud_proof() {
                    tracing::info!(
                        "RECV fraud_proof: from={}..., event={}...",
                        &fp.sender[..12.min(fp.sender.len())],
                        &fp.event_id[..16.min(fp.event_id.len())]
                    );
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.handle_fraud_proof(fp),
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::error!("handle_fraud_proof timed out after 5s");
                            break;
                        }
                    }
                }
                metrics::record_run_loop_phase("drain_fraud_proofs", phase_start.elapsed());
            }

            // Handle responses (for auto-recording attestations)
            {
                let phase_start = std::time::Instant::now();
                while let Some(response) = self.nostr.try_recv_response() {
                    tracing::info!(
                        "RECV response: request={}..., success={}, error={:?}",
                        &response.request_id[..16.min(response.request_id.len())],
                        response.success,
                        response.error.as_deref().unwrap_or("")
                    );
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.handle_ledger_response(response),
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::error!("handle_ledger_response timed out after 5s");
                            break;
                        }
                    }
                }
                metrics::record_run_loop_phase("drain_responses", phase_start.elapsed());
            }

            // Handle ledger updates (validate and auto-dispute on invalid)
            {
                let phase_start = std::time::Instant::now();
                while let Some(update) = self.nostr.try_recv_ledger_update() {
                    tracing::info!(
                        "RECV update: ledger={}..., seq={}",
                        &update.ledger_id[..16.min(update.ledger_id.len())],
                        update.update.sequence_number
                    );
                    self.handle_ledger_update(update).await;
                }
                metrics::record_run_loop_phase("drain_updates", phase_start.elapsed());
            }

            // Check for outbound messages (non-blocking)
            while let Ok(outbound) = self.outbound_rx.lock().unwrap().try_recv() {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    self.nostr.send_message(outbound.peer, outbound.message),
                )
                .await
                {
                    Ok(Err(e)) => tracing::error!("Failed to send message: {}", e),
                    Err(_) => {
                        tracing::error!("send_message timed out after 5s");
                        break;
                    }
                    _ => {}
                }
            }

            // Update adaptive timeout: use short timeout next iteration if we
            // processed any requests OR have active spawned tasks (cosign responses
            // need process_events + drain_responses to route to the oneshot channel).
            // With persistent per-ledger workers, always use short timeout when
            // workers exist (they may have in-flight cosign requests needing event pump).
            let has_workers = {
                let workers = self.ledger_workers.lock().unwrap();
                !workers.is_empty()
            };
            had_requests_last_iteration = subscription_batch_size > 0 || has_workers;

            // Record run loop iteration duration
            let loop_elapsed = loop_start.elapsed();
            metrics::record_run_loop_iteration(loop_elapsed);
            if loop_elapsed.as_millis() > 500 {
                tracing::warn!("[SLOW_LOOP] Run loop iteration took {:?}", loop_elapsed);
            }
        }
    }
}
