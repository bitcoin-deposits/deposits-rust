use super::*;
use deposits_signer_api::Signer as _;

impl Node {
    /// Create a new node
    #[tracing::instrument(name = "Node::new", skip(config))]
    pub async fn new(config: NodeConfig) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        // Build the Signer abstraction. Two paths:
        //   - LocalSigner: built from the seed via `from_xpriv_with_nostr`
        //     so it can derive wallet account xpubs / sibling Nostr keys
        //     in addition to the operator key. Default when
        //     --signer-socket is not configured.
        //   - RemoteSigner: connect to deposits-signer over Unix socket,
        //     verify the pinned signer pubkey. Operator-protocol signs
        //     (the slashable ones) flow over the wire; anti-equivocation
        //     policy is active on the signer side.
        let signer: std::sync::Arc<dyn deposits_signer_api::Signer> = match &config.signer {
            None => {
                let xpriv = bitcoin::bip32::Xpriv::new_master(config.network, &config.seed)
                    .map_err(|e| Error::Wallet(format!("xpriv from seed: {}", e)))?;
                let local = deposits_signer_api::LocalSigner::from_xpriv_with_nostr(xpriv)
                    .map_err(|e| {
                        Error::Wallet(format!("LocalSigner::from_xpriv_with_nostr: {}", e))
                    })?;
                std::sync::Arc::new(local)
            }
            Some(sig_cfg) => {
                let transport_secret = Self::load_or_init_transport_secret(&config.data_dir)?;
                let remote = crate::remote_signer::RemoteSigner::connect(
                    &sig_cfg.socket_path,
                    transport_secret,
                    sig_cfg.signer_pubkey,
                    config.network,
                )
                .map_err(|e| {
                    Error::Wallet(format!(
                        "connect to deposits-signer at {}: {} \
                         (have you `deposits-signer trust add`'d this node's \
                         transport pubkey?)",
                        sig_cfg.socket_path.display(),
                        e
                    ))
                })?;
                std::sync::Arc::new(remote)
            }
        };
        let node_id = signer.pubkey();

        // Build the node-level wallet from the signer's master xpub.
        // Watch-only — the daemon never holds the master xpriv. Same
        // `m/0/*` and `m/1/*` derivation as the legacy seed-embedded
        // descriptor, so addresses are stable across the cutover.
        let wallet = Arc::new(Wallet::new(
            &*signer,
            config.network,
            config.data_dir.join("wallet"),
            config.electrum_url.clone(),
        )?);

        // Reload per-ledger wallets from disk. Each ledger we've ever
        // opened owns a `<data_dir>/wallet/ledgers/<ledger_id>/` dir
        // with its own BDK descriptor account; rebuilding the
        // `LedgerWallet` asks the signer for the watch-only xpub at
        // that account, so the daemon never holds the per-ledger
        // private material.
        let (ledger_wallets, next_ledger_account) = {
            let mut map: HashMap<String, Arc<crate::ledger_wallet::LedgerWallet>> = HashMap::new();
            let mut max_seen: i64 = -1;
            let dir = config.data_dir.join("wallet").join("ledgers");
            if dir.exists() {
                for entry in std::fs::read_dir(&dir).map_err(|e| {
                    Error::Wallet(format!("read ledger wallets dir {:?}: {}", dir, e))
                })? {
                    let entry = entry.map_err(|e| {
                        Error::Wallet(format!("read ledger wallets dir entry: {}", e))
                    })?;
                    if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    let ledger_id = entry.file_name().to_string_lossy().to_string();
                    let lw = match crate::ledger_wallet::LedgerWallet::load(
                        &*signer,
                        config.network,
                        &ledger_id,
                        &config.data_dir,
                        config.electrum_url.clone(),
                    ) {
                        Ok(lw) => lw,
                        Err(e) => {
                            tracing::warn!("skipping ledger wallet at {:?}: {}", entry.path(), e);
                            continue;
                        }
                    };
                    max_seen = max_seen.max(lw.account_index() as i64);
                    map.insert(ledger_id, Arc::new(lw));
                }
            }
            tracing::info!(
                "Loaded {} per-ledger wallet(s); next BIP-32 account = {}",
                map.len(),
                max_seen + 1
            );
            (map, (max_seen + 1) as u32)
        };

        // Resolve the daemon's *delegate Nostr key* — used as the
        // daemon's Nostr identity (`self.keys` inside NostrTransport).
        // Outbound DMs and gift-wraps from the daemon are signed by
        // the delegate; advertisements are still signed by the
        // operator key via the Signer. Matches the delegation pattern
        // documented in DEP-04: wallets pin operator, address messages
        // to delegate. The dual-decrypt path on inbound
        // (`nip04_decrypt_with_fallback`) keeps legacy wallets working.
        //
        // Prefer a persisted `delegate_secret` if present (so the
        // pubkey doesn't change for nodes set up before derivation was
        // wired in); otherwise ask the signer to issue a deterministic
        // sibling secret (`m/85'/0'/0'/0/0` for LocalSigner) — that
        // form is recoverable from the seed alone, no on-disk
        // persistence required.
        let delegate_secret = match Self::load_persisted_delegate_secret(&config.data_dir)? {
            Some(sk) => sk,
            None => {
                let bytes = signer.issue_nostr_secret().map_err(|e| {
                    Error::Wallet(format!(
                        "signer cannot issue a delegate Nostr secret: {} \
                         (LocalSigner needs from_xpriv_with_nostr; \
                         RemoteSigner needs a server that supports IssueNostrSecret)",
                        e
                    ))
                })?;
                bitcoin::secp256k1::SecretKey::from_slice(&bytes)
                    .map_err(|e| Error::Wallet(format!("issued nostr secret invalid: {}", e)))?
            }
        };
        let delegate_pubkey = PublicKey::from_secret_key(&secp, &delegate_secret);

        // Store relay URL for later use
        let relay_url = config.relays.first().cloned().unwrap_or_default();

        // Create nostr transport (fast relays for subs/publish, slow relays for gap-fill)
        let nostr = NostrTransport::new_with_slow(
            delegate_secret,
            config.relays,
            config.slow_relays,
            config.skip_nostr_verify,
        )
        .await?;
        // Tell the transport about our delegate so every published
        // advertisement carries `LedgerAdvertisement.delegate_pubkey`
        // for delegation-aware wallets.
        nostr.set_delegate_pubkey(delegate_pubkey);
        // Wire the Signer + operator pubkey into the transport so it can
        //   1. sign advertisements with the operator key (BIP-340 over event id)
        //   2. NIP-04-decrypt inbound DMs that are still addressed to the
        //      operator pubkey (legacy wallets), via the Signer's
        //      raw-X-ECDH method
        //   3. accept admin envelopes whose `#p` tag is the operator pubkey
        nostr.set_signer(std::sync::Arc::clone(&signer));
        nostr.set_operator_pubkey(node_id);

        // Create handler with data_dir for ledger persistence
        let handler_data_dir = config.data_dir.join("wallet");
        let enable_metrics_emitter =
            std::env::var("DEPOSITS_ENABLE_METRICS_EMITTER").as_deref() == Ok("1");
        let (handler, outbound_rx) = DepositsHandler::new(
            std::sync::Arc::clone(&signer),
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

        // Spawn one actor per loaded ledger. Each actor co-owns the
        // ledger's `Arc<RwLock<Ledger>>` with `handler.ledgers` so
        // its commit/apply path is authoritative for every reader.
        // Lazy-spawn (`Node::ensure_actor_for`) covers ledgers
        // created after this point.
        let actor_pool_span = tracing::info_span!("actor_pool_spawn").entered();
        let (actor_outbox_tx, actor_outbox_rx) =
            tokio::sync::mpsc::unbounded_channel::<(String, super::ledger_actor::LedgerOutbound)>();
        let mut ledger_actors: HashMap<String, super::ledger_actor::LedgerActorHandle> =
            HashMap::new();
        {
            let ledgers = handler_arc.ledgers.lock().unwrap();
            for (lid, arc) in ledgers.iter() {
                let shared_ledger = Arc::clone(arc);
                let (tx, rx) = tokio::sync::mpsc::channel::<super::ledger_actor::LedgerEvent>(64);
                let apply_wakeup = Arc::new(tokio::sync::Notify::new());
                let actor = super::ledger_actor::LedgerActor {
                    inbox: rx,
                    outbox: actor_outbox_tx.clone(),
                    ledger: shared_ledger,
                    ledger_id: lid.clone(),
                    signer: handler_arc.signer.clone(),
                    handler: handler_arc.clone(),
                    apply_wakeup: Arc::clone(&apply_wakeup),
                };
                tokio::spawn(actor.run());
                ledger_actors.insert(
                    lid.clone(),
                    super::ledger_actor::LedgerActorHandle {
                        inbox: tx,
                        apply_wakeup,
                    },
                );
            }
        }
        drop(actor_pool_span);
        let actor_outbox_tx_for_node = actor_outbox_tx;
        // Park the outbox receiver on `Self` for `run()` to pick up.
        // The drainer needs `Arc<Node>` for `request_cosign` /
        // `broadcast_ledger_update` callbacks that don't exist
        // until `Self` is constructed. `main_loop::run` has
        // `&Arc<Self>` in scope, so it spawns the drainer there.
        let actor_outbox_rx_parked = Mutex::new(Some(actor_outbox_rx));
        // Notify shared between the outbox drainer (signal) and
        // main_loop's wakeup task (await). `MaybeConfiscate` events
        // hit `notify_one` so `auto_confiscate` runs immediately
        // instead of waiting up to `periodic_interval`.
        let dispute_wakeup = Arc::new(tokio::sync::Notify::new());

        // Subscribe globally (4 compacted kind filters for all event types).
        // CLI commands don't call start(), so we do this here too.
        if let Err(e) = nostr.subscribe_global().await {
            tracing::warn!("Failed to subscribe globally during init: {}", e);
        }

        tracing::info!("Node created with ID: {}", node_id);

        let node_id_hex = hex::encode(node_id.serialize());
        let admin_pubkey = Self::load_admin_pubkey(&config.data_dir);

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
            rotating_ledgers: Arc::new(Mutex::new(std::collections::HashSet::new())),
            cosign_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
            dispute_wakeup,
            pending_invoices: Arc::new(Mutex::new(Self::load_pending_invoices(&config.data_dir))),
            processed_requests: Mutex::new(std::collections::HashSet::new()),
            processed_requests_prev: Mutex::new(std::collections::HashSet::new()),
            sent_events: Mutex::new(std::collections::HashSet::new()),
            sent_events_prev: Mutex::new(std::collections::HashSet::new()),
            revealed_ledgers: Mutex::new(std::collections::HashSet::new()),
            expiry_stand_down_running: std::sync::atomic::AtomicBool::new(false),
            resync_last_broadcast: Mutex::new(HashMap::new()),
            active_ledger_tasks: Mutex::new(HashMap::new()),
            ledger_workers: Mutex::new(HashMap::new()),
            cosign_workers: Mutex::new(HashMap::new()),
            ledger_actors: Mutex::new(ledger_actors),
            actor_outbox_tx: actor_outbox_tx_for_node,
            actor_outbox_rx: actor_outbox_rx_parked,
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
            operator_name: config.operator_name.clone(),
            data_dir: config.data_dir,
            relay_url,
            fast_poll: config.fast_poll,
            rotate_before_expiry_days: config.rotate_before_expiry_days,
            joined_ledger_cache: Mutex::new(None),
            joined_ledger_cache_versions: Mutex::new(HashMap::new()),
            imported_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            pending_confiscations: Mutex::new(HashMap::new()),
            pending_subset_claims: Mutex::new(HashMap::new()),
            wallet_sync_running: std::sync::atomic::AtomicBool::new(false),
            height_sync_running: std::sync::atomic::AtomicBool::new(false),
            stale_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            pending_fork_publications: Mutex::new(std::collections::HashSet::new()),
            pending_dereliction_watches: Mutex::new(HashMap::new()),
            reported_derelictions: Mutex::new(std::collections::HashSet::new()),
            vault_scanned: Mutex::new(None),
            reported_vault_spends: Mutex::new(std::collections::HashSet::new()),
            known_confiscation_txids: Mutex::new(std::collections::HashSet::new()),
            seen_lottery_reveals: Mutex::new(HashMap::new()),
            last_relay_fetch_times: Mutex::new(HashMap::new()),
            cosign_member_cache: Mutex::new(HashMap::new()),
            dirty_ledgers: Mutex::new(std::collections::HashSet::new()),
            operator_of_cache: Mutex::new(HashMap::new()),
            admin_pubkey,
            ledger_wallets: Arc::new(RwLock::new(ledger_wallets)),
            next_ledger_account: Mutex::new(next_ledger_account),
            electrum_url: config.electrum_url,
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
                tracing::warn!("Ignoring malformed admin.npub ({}): {}", path.display(), e);
                None
            }
        }
    }

    /// Sync the wallet with the blockchain (full — expensive)
    pub fn sync_wallet(&self) -> Result<(), Error> {
        self.wallet.sync()
    }

    /// Per-deposit balance cap (msats). 0 = unlimited. Sourced from
    /// MAX_DEPOSIT_BALANCE_MSATS env at startup. Surfaced on the
    /// ledger advertisement so wallets / lnurl gateways can reflect
    /// it as `maxSendable` instead of letting depositors hit the cap
    /// only after paying.
    pub fn max_deposit_balance_msats(&self) -> u64 {
        self.max_deposit_balance_msats
    }

    /// Operator display name (`--name` / `NODE_NAME`). Used by the
    /// ad-publish path to refresh the name on every republish so an
    /// operator who set their name after the initial publish doesn't
    /// have it silently dropped.
    pub fn operator_name(&self) -> Option<&str> {
        self.operator_name.as_deref()
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
        use deposits_signer_api::SignContext;

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
        let ledger_id_bytes = ledger.ledger_id();

        if let Some(update) = ledger.history.last_mut() {
            // DEP-02 v2 operator digest.
            // See `SignedLedgerUpdate::operator_digest`.
            let digest = update.operator_digest();
            let ctx = SignContext::operator_update(ledger_id_bytes, update.sequence_number);
            update.operator_signature = self
                .handler
                .signer
                .bip340_sign(&ctx, &digest)
                .map_err(|e| Error::Protocol(format!("operator sign failed: {}", e)))?;
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

    /// Spawn a `LedgerActor` for `ledger_id` if one doesn't already exist.
    ///
    /// At `Node::new` time we spawn one actor per ledger present on
    /// disk — but ledgers can also appear at runtime (operator opens
    /// a new ledger via admin, member imports via QuorumJoin, daemon
    /// receives inbound for an unknown id). Without a corresponding
    /// actor, that ledger's inbound + commit events have nowhere to
    /// route, since the actor is the single writer.
    ///
    /// Idempotent: returns immediately if an actor is already registered.
    /// Load (or generate) the daemon's *delegate Nostr key*. This is the
    /// key the daemon uses for Nostr-layer operations — Kind 9100 event
    /// signing, NIP-04 ECDH for inbound DMs, gift-wrap envelopes. The
    /// operator's protocol-level key (which lives in the Signer when
    /// running with deposits-signer) only signs Kind 39100 advertisement
    /// events; the advertisement carries `delegate_pubkey` so wallets
    /// know to address subsequent traffic here.
    ///
    /// Read a previously-persisted delegate Nostr secret from
    /// `<data-dir>/delegate_secret` if present. Pre-derivation
    /// daemons wrote a random secret here on first run; we keep
    /// reading it so existing operators don't see their delegate
    /// pubkey change (every wallet that has them pinned would break).
    /// New deployments skip persistence entirely and derive the
    /// secret from the seed via `Signer::issue_nostr_secret`.
    pub fn load_persisted_delegate_secret(
        data_dir: &std::path::Path,
    ) -> Result<Option<bitcoin::secp256k1::SecretKey>, Error> {
        let path = data_dir.join("delegate_secret");
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            Error::Wallet(format!("read delegate_secret {}: {}", path.display(), e))
        })?;
        let bytes = hex::decode(raw.trim())
            .map_err(|e| Error::Wallet(format!("delegate_secret hex: {}", e)))?;
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes)
            .map_err(|e| Error::Wallet(format!("delegate_secret: {}", e)))?;
        Ok(Some(sk))
    }

    /// Load (or generate) the daemon's transport keypair under
    /// `<data_dir>/transport_secret`. Returns the secret; the caller derives
    /// the pubkey for handshake. On first run we generate fresh, write 0600,
    /// and log the public side so the operator can `deposits-signer trust add`.
    pub fn load_or_init_transport_secret(
        data_dir: &std::path::Path,
    ) -> Result<bitcoin::secp256k1::SecretKey, Error> {
        Self::load_or_init_persistent_secret(data_dir, "transport_secret", None)
    }

    /// Generic helper: load or generate a 32-byte secret persisted under
    /// `<data_dir>/<name>`. If `pubkey_filename` is `Some`, also writes
    /// the corresponding compressed pubkey to `<data_dir>/<pubkey_filename>`
    /// (0644) so external tooling on the same host can read it without
    /// invoking the daemon's CLI.
    fn load_or_init_persistent_secret(
        data_dir: &std::path::Path,
        name: &str,
        pubkey_filename: Option<&str>,
    ) -> Result<bitcoin::secp256k1::SecretKey, Error> {
        use std::os::unix::fs::PermissionsExt;
        let path = data_dir.join(name);
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| Error::Wallet(format!("read {} {}: {}", name, path.display(), e)))?;
            let bytes = hex::decode(raw.trim())
                .map_err(|e| Error::Wallet(format!("{} hex: {}", name, e)))?;
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes)
                .map_err(|e| Error::Wallet(format!("{}: {}", name, e)))?;
            return Ok(sk);
        }
        // Generate fresh.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Wallet(format!("create_dir_all {}: {}", parent.display(), e))
            })?;
        }
        use bitcoin::secp256k1::rand::rngs::OsRng;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let body = hex::encode(sk.secret_bytes());
        let mut f = std::fs::File::create(&path)
            .map_err(|e| Error::Wallet(format!("create {} {}: {}", name, path.display(), e)))?;
        use std::io::Write;
        f.write_all(body.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| Error::Wallet(format!("write {}: {}", name, e)))?;
        let mut perms = f
            .metadata()
            .map_err(|e| Error::Wallet(format!("stat {}: {}", name, e)))?
            .permissions();
        perms.set_mode(0o600);
        f.set_permissions(perms)
            .map_err(|e| Error::Wallet(format!("chmod {}: {}", name, e)))?;

        // Optionally drop the public side for tooling that needs to
        // discover the pubkey without invoking the CLI.
        if let Some(pubkey_name) = pubkey_filename {
            let pub_path = data_dir.join(pubkey_name);
            let pub_body = hex::encode(pk.serialize());
            let mut pf = std::fs::File::create(&pub_path).map_err(|e| {
                Error::Wallet(format!(
                    "create {} {}: {}",
                    pubkey_name,
                    pub_path.display(),
                    e
                ))
            })?;
            pf.write_all(pub_body.as_bytes())
                .and_then(|_| pf.write_all(b"\n"))
                .map_err(|e| Error::Wallet(format!("write {}: {}", pubkey_name, e)))?;
            let mut pub_perms = pf
                .metadata()
                .map_err(|e| Error::Wallet(format!("stat {}: {}", pubkey_name, e)))?
                .permissions();
            pub_perms.set_mode(0o644);
            pf.set_permissions(pub_perms)
                .map_err(|e| Error::Wallet(format!("chmod {}: {}", pubkey_name, e)))?;
        }

        if name == "transport_secret" {
            tracing::warn!(
                "Generated daemon transport keypair: pubkey={}. Add it to the \
                 signer's allowlist with `deposits-signer trust add --data-dir \
                 <signer-data-dir> {}` before the next handshake will succeed.",
                hex::encode(pk.serialize()),
                hex::encode(pk.serialize()),
            );
        }
        Ok(sk)
    }

    /// Drop any existing actor for `ledger_id` and spawn a fresh one bound to
    /// the CURRENT `handler.ledgers` Arc.
    ///
    /// A ledger's `LedgerActor` (the single writer) captures a *clone* of the
    /// specific `Arc<RwLock<Ledger>>` present at spawn time. Two things can
    /// later leave that clone orphaned from the map: `reimport_joined_ledger`'s
    /// "chain break → purge + reinsert" (a brand-new Arc), and a dispute-fork
    /// promotion (the base entry adopts the resolved fork's state). The actor
    /// then keeps committing against a stale allocation — so the first fresh
    /// `deposit_open` on a recovered ledger staged at an already-taken sequence
    /// and the quorum refused it as an equivocation. Removing the handle closes
    /// the old actor's inbox (its `recv` loop ends once the last sender drops);
    /// `ensure_actor_for` then rebinds to the current Arc.
    pub(crate) fn respawn_actor_for(&self, ledger_id: &str) {
        self.ledger_actors.lock().unwrap().remove(ledger_id);
        self.ensure_actor_for(ledger_id);
    }

    pub(crate) fn ensure_actor_for(&self, ledger_id: &str) {
        {
            let map = self.ledger_actors.lock().unwrap();
            if map.contains_key(ledger_id) {
                return;
            }
        }
        let shared_ledger = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                // Share the handler's Arc directly so the actor's
                // writes are visible to every reader going through
                // `handler.ledgers`.
                Some(arc) => Arc::clone(arc),
                None => return,
            }
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<super::ledger_actor::LedgerEvent>(64);
        let apply_wakeup = Arc::new(tokio::sync::Notify::new());
        let actor = super::ledger_actor::LedgerActor {
            inbox: rx,
            outbox: self.actor_outbox_tx.clone(),
            ledger: shared_ledger,
            ledger_id: ledger_id.to_string(),
            signer: self.handler.signer.clone(),
            handler: self.handler.clone(),
            apply_wakeup: Arc::clone(&apply_wakeup),
        };
        tokio::spawn(actor.run());
        let mut map = self.ledger_actors.lock().unwrap();
        map.entry(ledger_id.to_string())
            .or_insert(super::ledger_actor::LedgerActorHandle {
                inbox: tx,
                apply_wakeup,
            });
        tracing::debug!(
            "ensure_actor_for: spawned actor for ledger {}",
            &ledger_id[..16.min(ledger_id.len())]
        );
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

        // Snapshot the history under the lock, then drop the guard before
        // awaiting. The RwLockReadGuard is !Send so it can't be held
        // across an await in a `tokio::spawn`-ed future (which is exactly
        // how the periodic task hub runs us).
        let history = {
            let ledger = ledger_arc.read().unwrap();
            ledger.history.clone()
        };

        let mut count = 0;
        let mut failed = 0usize;
        for update in &history {
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
                    failed += 1;
                    tracing::warn!(
                        "Failed to broadcast update seq={}: {}",
                        update.sequence_number,
                        e
                    );
                }
            }
        }

        // A partial broadcast is a failure, not a count: a caller that
        // logged success on `Ok` hid ref3's dispute fork (see `fork_publish`).
        if failed > 0 {
            return Err(Error::Protocol(format!(
                "{} of {} updates not broadcast",
                failed,
                history.len()
            )));
        }
        Ok(count)
    }
}
