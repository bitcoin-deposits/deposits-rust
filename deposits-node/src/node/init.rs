use super::*;

impl Node {
    /// Create a new node
    pub async fn new(config: NodeConfig) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        // Create wallet
        let wallet = Arc::new(Wallet::new(
            config.seed,
            config.network,
            config.data_dir.join("wallet"),
            config.electrum_url.clone(),
        )?);

        let secret_key = wallet.operator_secret();
        let node_id = PublicKey::from_secret_key(&secp, &secret_key);

        // Store relay URL for later use
        let relay_url = config.relays.first().cloned().unwrap_or_default();

        // Create nostr transport (fast relays for subs/publish, slow relays for gap-fill)
        let nostr = NostrTransport::new_with_slow(
            secret_key,
            config.relays,
            config.slow_relays,
            config.skip_nostr_verify,
        )
        .await?;

        // Create handler with data_dir for ledger persistence
        let handler_data_dir = config.data_dir.join("wallet");
        let enable_metrics_emitter =
            std::env::var("DEPOSITS_ENABLE_METRICS_EMITTER").as_deref() == Ok("1");
        let (handler, outbound_rx) = DepositsHandler::new(
            secret_key,
            wallet.clone(),
            handler_data_dir,
            enable_metrics_emitter,
        );

        // Start periodic deposit metrics emitter if enabled
        let handler_arc = Arc::new(handler);
        handler_arc.start_metrics_emitter();

        // Load existing deposit offers from disk
        let deposit_offers = Self::load_deposit_offers(&config.data_dir)?;

        // Load existing withdrawals from disk
        let withdrawals = Self::load_withdrawals(&config.data_dir)?;

        // Set response filter for relay-side #l tag filtering (reduces fan-out ~75%)
        // Collect owned ledger IDs from already-loaded handler ledgers
        {
            let ledgers = handler_arc.ledgers.lock().unwrap();
            let owned_ids: Vec<String> = ledgers
                .iter()
                .filter(|(_, larc)| larc.read().unwrap().operator_key() == node_id)
                .map(|(_, larc)| larc.read().unwrap().ledger_id_hex())
                .collect();
            if !owned_ids.is_empty() {
                nostr.set_response_ledger_filter(owned_ids);
            }
        }

        // Subscribe globally (4 compacted kind filters for all event types).
        // CLI commands don't call start(), so we do this here too.
        if let Err(e) = nostr.subscribe_global().await {
            tracing::warn!("Failed to subscribe globally during init: {}", e);
        }

        tracing::info!("Node created with ID: {}", node_id);

        let node_id_hex = hex::encode(node_id.serialize());
        let admin_pubkey = Self::load_admin_pubkey(&config.data_dir);
        let seed_for_buffer_ops = config.seed;

        Ok(Self {
            node_id,
            node_id_hex,
            secp,
            wallet,
            nostr,
            handler: handler_arc,
            outbound_rx: Mutex::new(outbound_rx),
            deposit_offers: Mutex::new(deposit_offers),
            withdrawals: Mutex::new(withdrawals),
            pending_cosign_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_consent_requests: Arc::new(Mutex::new(HashMap::new())),
            staging_locks: Mutex::new(HashMap::new()),
            cosign_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
            pending_invoices: Arc::new(Mutex::new(Self::load_pending_invoices(&config.data_dir))),
            processed_requests: Mutex::new(std::collections::HashSet::new()),
            processed_requests_prev: Mutex::new(std::collections::HashSet::new()),
            sent_events: Mutex::new(std::collections::HashSet::new()),
            sent_events_prev: Mutex::new(std::collections::HashSet::new()),
            active_ledger_tasks: Mutex::new(HashMap::new()),
            ledger_workers: Mutex::new(HashMap::new()),
            cosign_workers: Mutex::new(HashMap::new()),
            deposit_access_control: std::env::var("DEPOSIT_ACCESS_CONTROL")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            deposit_allowlist: RwLock::new(Self::load_list(
                &config.data_dir,
                "deposit_allowlist.txt",
            )),
            deposit_denylist: RwLock::new(Self::load_list(
                &config.data_dir,
                "deposit_denylist.txt",
            )),
            deposit_domain_allowlist: RwLock::new(Self::load_list(
                &config.data_dir,
                "deposit_domain_allowlist.txt",
            )),
            attestation_verifier_pubkey: std::env::var("ATTESTATION_VERIFIER_PUBKEY")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    // Normalize npub/hex to hex at load time
                    match nostr_sdk::PublicKey::parse(&s) {
                        Ok(pk) => pk.to_hex(),
                        Err(_) => s,
                    }
                }),
            max_deposit_balance_msats: std::env::var("MAX_DEPOSIT_BALANCE_MSATS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            data_dir: config.data_dir,
            relay_url,
            fast_poll: config.fast_poll,
            joined_ledger_cache: Mutex::new(None),
            joined_ledger_cache_versions: Mutex::new(HashMap::new()),
            imported_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            pending_confiscations: Mutex::new(HashMap::new()),
            stale_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            last_relay_fetch_times: Mutex::new(HashMap::new()),
            cosign_member_cache: Mutex::new(HashMap::new()),
            dirty_ledgers: Mutex::new(std::collections::HashSet::new()),
            operator_of_cache: Mutex::new(HashMap::new()),
            admin_pubkey,
            seed: seed_for_buffer_ops,
        })
    }

    /// Load the admin pubkey written by `deposits-node bootstrap init`.
    /// Accepts either `npub1...` (bech32) or 64-char hex. Returns None if the
    /// file is missing or malformed; callers then have no admin delegation
    /// and must operate with the operator seed directly.
    fn load_admin_pubkey(data_dir: &std::path::Path) -> Option<nostr_sdk::PublicKey> {
        let path = data_dir.join("admin.npub");
        let raw = std::fs::read_to_string(&path).ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        match nostr_sdk::PublicKey::parse(trimmed) {
            Ok(pk) => {
                tracing::info!("Loaded admin pubkey from {}", path.display());
                Some(pk)
            }
            Err(e) => {
                tracing::warn!(
                    "Ignoring malformed admin.npub ({}): {}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    /// Sync the wallet with the blockchain (full — expensive)
    pub fn sync_wallet(&self) -> Result<(), Error> {
        self.wallet.sync()
    }

    /// Lightweight sync: just block height + hash (cheap)
    pub fn sync_block_height(&self) -> Result<(), Error> {
        self.wallet.sync_block_height()
    }

    /// Sign the last update in a ledger with our operator key
    ///
    /// Call this after appending an operation to sign the update before broadcasting.
    pub fn sign_last_update(&self, ledger_id: &str) -> Result<(), Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;

        // Get the ledger by ledger_id
        let ledger_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;

        let mut ledger = ledger_arc.write().unwrap();

        if let Some(update) = ledger.history.last_mut() {
            // Sign using operator_signing_data (cosign_data + all cosig_signatures)
            let data = update.operator_signing_data();
            let hash = sha256::Hash::hash(&data);
            let secp = &self.secp;
            let msg = Message::from_digest(*hash.as_byte_array());
            let keypair =
                bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);

            update.operator_signature = sig.serialize();
            tracing::debug!(
                "Signed update seq={} for ledger {}",
                update.sequence_number,
                &ledger_id[..16.min(ledger_id.len())]
            );
        }

        // Finalize state.hash = chain_hash = SHA256(content_hash || operator_signature)
        // so the next append_operation uses chain_hash as prev_hash (per protocol spec).
        ledger.finalize_chain_hash();

        Ok(())
    }

    /// Validate that the last in-memory update chains correctly from what's on disk.
    ///
    /// Call this after signing but before persisting + broadcasting. If the in-memory
    /// chain doesn't extend the disk state correctly (e.g., another process wrote a
    /// conflicting entry), returns an error to trigger rollback and retry.
    pub(crate) fn validate_chain_before_persist(&self, ledger_id: &str) -> Result<(), Error> {
        // The daemon is the sole writer — validate in-memory chain consistency
        // instead of re-reading the entire JSONL from disk.
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = ledgers
            .get(ledger_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
        let ledger = ledger_arc.read().unwrap();

        let len = ledger.history.len();
        if len < 2 {
            return Ok(());
        }

        // Check that the last entry chains from its predecessor
        let prev = &ledger.history[len - 2];
        let last = &ledger.history[len - 1];

        if last.sequence_number != prev.sequence_number + 1 {
            return Err(Error::Protocol(format!(
                "Sequence gap before persist: prev_seq={}, last_seq={}",
                prev.sequence_number, last.sequence_number,
            )));
        }

        // The protocol chains via chain_hash = SHA256(content_hash || operator_signature),
        // so previous_hash of the next entry must equal chain_hash() of the prior entry.
        let prev_chain_hash = prev.chain_hash();
        if last.previous_hash != prev_chain_hash {
            return Err(Error::Protocol(format!(
                "Hash chain break before persist: seq={} prev_hash={}... but seq={} chain_hash={}...",
                last.sequence_number,
                hex::encode(&last.previous_hash[..8]),
                prev.sequence_number,
                hex::encode(&prev_chain_hash[..8]),
            )));
        }

        Ok(())
    }

    /// Sign with operator-only signature, validate chain, persist, and broadcast.
    ///
    /// Convenience method for paths where no co-signing is needed (no quorum members).
    /// Performs the full validate → persist → broadcast sequence.
    pub(crate) async fn operator_sign_persist_broadcast(
        &self,
        ledger_id: &str,
    ) -> Result<String, Error> {
        self.sign_last_update(ledger_id)?;
        self.validate_chain_before_persist(ledger_id)?;
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger: {}", e);
        }
        self.broadcast_last_update(ledger_id).await
    }

    /// Mark a ledger as dirty (modified but not yet persisted).
    /// Deferred persistence reduces write syscalls by batching multiple
    /// modifications into a single persist at the end of request processing.
    pub(crate) fn mark_ledger_dirty(&self, ledger_id: &str) {
        self.dirty_ledgers
            .lock()
            .unwrap()
            .insert(ledger_id.to_string());
    }

    /// Flush all dirty ledgers to disk.
    /// Called at the end of each request drain batch.
    pub(crate) fn flush_dirty_ledgers(&self) {
        let dirty: Vec<String> = self.dirty_ledgers.lock().unwrap().drain().collect();
        if dirty.is_empty() {
            return;
        }
        // Pre-check: if handler.ledgers is contended (orphaned JoinSet tasks),
        // defer ALL dirty ledgers to the next cycle rather than blocking the thread.
        if self.handler.ledgers.try_lock().is_err() {
            let mut d = self.dirty_ledgers.lock().unwrap();
            let count = dirty.len();
            for id in dirty {
                d.insert(id);
            }
            tracing::warn!(
                "flush_dirty_ledgers: ledgers lock contended, deferring {} ledgers",
                count
            );
            return;
        }
        for ledger_id in &dirty {
            if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
                tracing::warn!(
                    "Failed to persist dirty ledger {}: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e
                );
            }
        }
    }

    /// Broadcast the most recent ledger update to Nostr
    ///
    /// Call this after appending an operation to a ledger to ensure the update
    /// is published to the Nostr relay for other participants to see.
    pub async fn broadcast_last_update(&self, ledger_id: &str) -> Result<String, Error> {
        // Get the ledger by ledger_id and clone the update.
        // Clone before the await to avoid holding RwLockReadGuard across await (not Send).
        let (update, seq) = {
            let ledger_arc = self
                .handler
                .ledgers
                .lock()
                .unwrap()
                .get(ledger_id)
                .cloned()
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            let update = ledger
                .history
                .last()
                .ok_or_else(|| Error::Protocol("Ledger has no updates".to_string()))?
                .clone();
            let seq = update.sequence_number;
            (update, seq)
        };

        // Broadcast to Nostr
        let event_id = self.nostr.broadcast_ledger_update(&update).await?;
        tracing::debug!("Broadcast update seq={} to Nostr: {}", seq, &event_id[..16]);

        Ok(event_id)
    }

    /// Broadcast all ledger updates to Nostr
    ///
    /// Use this when initializing a ledger (e.g., after ledger_open) to broadcast
    /// all initial operations (LedgerOpen, LedgerOpen, etc.)
    pub async fn broadcast_all_updates(&self, ledger_id: &str) -> Result<usize, Error> {
        // Get the ledger by ledger_id
        let ledger_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;

        let ledger = ledger_arc.read().unwrap();

        let mut count = 0;
        for update in &ledger.history {
            match self.nostr.broadcast_ledger_update(update).await {
                Ok(event_id) => {
                    tracing::debug!(
                        "Broadcast update seq={} to Nostr: {}",
                        update.sequence_number,
                        &event_id[..16]
                    );
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to broadcast update seq={}: {}",
                        update.sequence_number,
                        e
                    );
                }
            }
        }

        Ok(count)
    }
}
