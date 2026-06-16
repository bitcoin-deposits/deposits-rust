//! Admin request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

/// Outcome of [`Node::internal_buffer_open`]. Mirrors the JSON the
/// admin request returns, but typed so the (internal) drip auto-task
/// caller doesn't have to round-trip through JSON.
pub struct BufferOpenOutcome {
    pub index: u32,
    pub deposit_pubkey_hex: String,
    pub deposit_id_hex: String,
    pub ledger_id: String,
}

impl Node {
    /// Read the list of buffer indices this node tracks.
    /// `pub(crate)` so the drip auto-task can look up its plan's
    /// buffer-deposit entry without going through the admin RPC.
    pub(crate) fn load_buffer_indices(&self) -> Vec<BufferIndexEntry> {
        let path = self.data_dir.join("buffer_indices.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn save_buffer_indices(&self, entries: &[BufferIndexEntry]) -> Result<(), String> {
        let path = self.data_dir.join("buffer_indices.json");
        let raw = serde_json::to_string_pretty(entries)
            .map_err(|e| format!("serialize buffer_indices: {}", e))?;
        std::fs::write(&path, raw).map_err(|e| format!("write buffer_indices: {}", e))
    }

    /// Pick the next unused buffer index. Starts at 1_000_000 to leave
    /// the low-numbered range (0..) for customer-derived wallet indices,
    /// so running a customer wallet from the same seed won't collide.
    fn next_buffer_index(&self, existing: &[BufferIndexEntry]) -> u32 {
        const BUFFER_INDEX_BASE: u32 = 1_000_000;
        let max_used = existing
            .iter()
            .filter(|e| e.index >= BUFFER_INDEX_BASE)
            .map(|e| e.index)
            .max();
        max_used.map(|i| i + 1).unwrap_or(BUFFER_INDEX_BASE)
    }

    /// Open an operator-owned buffer deposit, no auth/request scaffolding.
    /// Internal — shared between `process_admin_buffer_open_request` (the
    /// admin-RPC entry) and `auto_drip_self_liquidity` (the periodic
    /// drip ticker). `index_override = None` auto-allocates from the
    /// 1M+ range; `ledger_id_override = None` uses the primary owned
    /// ledger.
    pub(crate) async fn internal_buffer_open(
        &self,
        ledger_id_override: Option<String>,
        index_override: Option<u32>,
    ) -> Result<BufferOpenOutcome, String> {
        let mut entries = self.load_buffer_indices();
        let index = index_override.unwrap_or_else(|| self.next_buffer_index(&entries));
        if entries.iter().any(|e| e.index == index) {
            return Err(format!("buffer index {} already opened", index));
        }
        let pk = self
            .handler
            .signer
            .pubkey_at(deposits_signer_api::KeyPath::Deposit { index })
            .map_err(|e| format!("signer pubkey_at(Deposit {{ index: {} }}): {}", index, e))?;
        let deposit_pubkey_hex = hex::encode(pk.serialize());

        let ledger_id = match ledger_id_override {
            Some(s) => s,
            None => match self.get_primary_ledger() {
                Some((lid, _)) => lid,
                None => return Err("no ledger open — run bootstrap reserves first".into()),
            },
        };
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
        let deposit_id_hex = hex::encode(deposit_id);

        let fees = deposits_core::FeeStructure {
            annualized_msats: 0,
            annualized_bps: 0,
            frequency_blocks: 2016,
        };
        self.open_deposit(&ledger_id, &descriptor, Some(fees), None, false)
            .await
            .map_err(|e| format!("open_deposit: {}", e))?;

        entries.push(BufferIndexEntry {
            index,
            ledger_id: ledger_id.clone(),
            deposit_pubkey: deposit_pubkey_hex.clone(),
        });
        if let Err(e) = self.save_buffer_indices(&entries) {
            tracing::warn!("couldn't persist buffer index: {}", e);
        }
        Ok(BufferOpenOutcome {
            index,
            deposit_pubkey_hex,
            deposit_id_hex,
            ledger_id,
        })
    }

    /// Open a buffer deposit AND fund it to `target_msats` in a single atomic
    /// `Batch([DepositOpen, InvoiceCredit])` update.
    ///
    /// The two ops are dependent — the credit references the deposit the open
    /// creates — so emitting them as separate cosign rounds raced quorum
    /// replication: a member asked to cosign the credit before it had applied
    /// the open rejected with `DepositNotFound`, and the drip stalled. Batching
    /// makes them one cosigned update; the batch applier applies inner ops
    /// sequentially against a scratch state, so the credit sees the deposit the
    /// open just created. Buffer index is registered only after the commit
    /// succeeds, so a failed batch leaves no dangling registration.
    pub(crate) async fn internal_buffer_open_and_fund(
        &self,
        ledger_id_override: Option<String>,
        target_msats: u64,
    ) -> Result<BufferOpenOutcome, String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::RngCore;

        let mut entries = self.load_buffer_indices();
        let index = self.next_buffer_index(&entries);
        let pk = self
            .handler
            .signer
            .pubkey_at(deposits_signer_api::KeyPath::Deposit { index })
            .map_err(|e| format!("signer pubkey_at(Deposit {{ index: {} }}): {}", index, e))?;
        let deposit_pubkey_hex = hex::encode(pk.serialize());

        let ledger_id = match ledger_id_override {
            Some(s) => s,
            None => match self.get_primary_ledger() {
                Some((lid, _)) => lid,
                None => return Err("no ledger open — run bootstrap reserves first".into()),
            },
        };
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
        let deposit_id_hex = hex::encode(deposit_id);

        let fees = deposits_core::FeeStructure {
            annualized_msats: 0,
            annualized_bps: 0,
            frequency_blocks: 2016,
        };
        let deposit_open = deposits_core::messages::LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.clone(),
            fees: Some(fees),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };

        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let invoice_id = format!("buffer-fill-{}-{}", index, hex::encode(nonce));
        let payment_hash = sha256::Hash::hash(invoice_id.as_bytes()).to_byte_array();
        let invoice_credit = deposits_core::messages::LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: target_msats,
            invoice_id,
            // Inner ops carry seq 0; the batch update carries the chain seq.
            sequence_number: 0,
            wallet_authorization: None,
        };

        let batch = deposits_core::messages::LedgerOperation::Batch(vec![deposit_open, invoice_credit]);
        self.commit_operation(&ledger_id, batch)
            .await
            .map_err(|e| format!("commit open+fund batch: {}", e))?;

        entries.push(BufferIndexEntry {
            index,
            ledger_id: ledger_id.clone(),
            deposit_pubkey: deposit_pubkey_hex.clone(),
        });
        if let Err(e) = self.save_buffer_indices(&entries) {
            tracing::warn!("couldn't persist buffer index: {}", e);
        }
        Ok(BufferOpenOutcome {
            index,
            deposit_pubkey_hex,
            deposit_id_hex,
            ledger_id,
        })
    }

    /// Fill an existing buffer deposit via synthetic InvoiceCredit.
    /// Returns the new balance in msats. Internal — see
    /// [`internal_buffer_open`] for the split rationale.
    pub(crate) async fn internal_buffer_fill(
        &self,
        index: u32,
        amount_msats: u64,
    ) -> Result<u64, String> {
        let entry = self
            .load_buffer_indices()
            .into_iter()
            .find(|e| e.index == index)
            .ok_or_else(|| format!("no buffer registered at index {}", index))?;
        let descriptor = format!("pk({})", entry.deposit_pubkey);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::RngCore;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let invoice_id = format!("buffer-fill-{}-{}", index, hex::encode(nonce));
        let payment_hash = sha256::Hash::hash(invoice_id.as_bytes()).to_byte_array();

        self.credit_deposit(&entry.ledger_id, deposit_id, amount_msats, payment_hash, invoice_id)
            .await
            .map_err(|e| format!("credit_deposit: {}", e))
    }

    /// Drain an existing buffer deposit via synthetic InvoiceLock +
    /// InvoiceFulfill, signed with the depositor's derived key.
    pub(crate) async fn internal_buffer_drain(
        &self,
        index: u32,
        amount_msats: u64,
    ) -> Result<u64, String> {
        let entry = self
            .load_buffer_indices()
            .into_iter()
            .find(|e| e.index == index)
            .ok_or_else(|| format!("no buffer registered at index {}", index))?;
        let descriptor = format!("pk({})", entry.deposit_pubkey);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::RngCore;
        let mut preimage = [0u8; 32];
        OsRng.fill_bytes(&mut preimage);
        let payment_id = sha256::Hash::hash(&preimage).to_byte_array();

        let op_nonce = deposits_core::signing::fresh_op_nonce();
        let op_expiry = u32::MAX;
        let lock_proto = deposits_core::messages::LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msats,
            payment_id,
            sequence_number: 0,
            nonce: op_nonce,
            expiry: op_expiry,
            witness: deposits_core::types::DescriptorWitness::new(),
        };
        let lock_sighash = deposits_core::dep16::operations::operation_sighash(&lock_proto)
            .ok_or_else(|| "dep-16 lock sighash failed".to_string())?;
        let lock_ctx = deposits_signer_api::SignContext::deposit(
            index,
            deposits_signer_api::SigPurpose::PaymentAuthorization,
        );
        let lock_sig = self
            .handler
            .signer
            .ecdsa_sign_sighash(&lock_ctx, &lock_sighash)
            .map_err(|e| format!("lock sign: {}", e))?;
        let lock_witness = deposits_core::types::DescriptorWitness {
            stack: vec![lock_sig.serialize_compact().to_vec()],
        };
        let fulfill_witness = lock_witness.clone();

        // Lock then fulfill in a single atomic batch. The fulfill depends on
        // the lock (it settles the OpenInvoiceLock the lock creates), so as
        // separate cosign rounds the fulfill would race a member that hadn't
        // applied the lock yet. Inner ops carry seq 0 (the witness sighash is
        // over the payment, not the chain seq); the batch update carries the
        // real sequence. Applier runs them in order on a scratch state.
        let lock_op = deposits_core::messages::LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msats,
            payment_id,
            sequence_number: 0,
            nonce: op_nonce,
            expiry: op_expiry,
            witness: lock_witness,
        };
        let fulfill_op = deposits_core::messages::LedgerOperation::InvoiceFulfill {
            deposit_id,
            amount: amount_msats,
            payment_id,
            preimage,
            sequence_number: 0,
            witness: fulfill_witness,
        };
        let batch =
            deposits_core::messages::LedgerOperation::Batch(vec![lock_op, fulfill_op]);
        self.commit_operation(&entry.ledger_id, batch)
            .await
            .map_err(|e| format!("commit drain batch: {}", e))?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(&entry.ledger_id)
                .and_then(|arc| {
                    arc.read()
                        .unwrap()
                        .state
                        .deposits
                        .get(&deposit_id)
                        .map(|d| d.balance)
                })
                .unwrap_or(0)
        };
        Ok(new_balance)
    }

    /// Read the current balance (msats) of the buffer deposit at
    /// `index`. Returns `None` if the buffer isn't registered or the
    /// deposit isn't yet on its ledger.
    pub(crate) fn internal_buffer_balance_msats(&self, index: u32) -> Option<u64> {
        let entry = self
            .load_buffer_indices()
            .into_iter()
            .find(|e| e.index == index)?;
        let descriptor = format!("pk({})", entry.deposit_pubkey);
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
        let ledgers = self.handler.ledgers.lock().unwrap();
        let arc = ledgers.get(&entry.ledger_id)?;
        let ledger = arc.read().unwrap();
        ledger.state.deposits.get(&deposit_id).map(|d| d.balance)
    }

    /// Admin: open a new buffer deposit on the operator's primary ledger.
    /// The deposit key is derived from the operator seed (same path the
    /// wallet uses), at an auto-advancing index persisted in
    /// `{data_dir}/buffer_indices.json`. Admins can later reconstruct
    /// the same keys from the mnemonic DM'd at bootstrap.
    ///
    /// Params:
    ///   index?          explicit BIP32 index (default: auto-advance)
    ///   ledger_id?      owned ledger to open on (default: primary)
    ///
    /// Returns `{index, deposit_pubkey, deposit_id, ledger_id}`.
    pub(crate) async fn process_admin_buffer_open_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        let index_override = request
            .params
            .get("index")
            .and_then(|v| v.as_u64())
            .map(|i| i as u32);
        let ledger_override = request
            .params
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        match self.internal_buffer_open(ledger_override, index_override).await {
            Ok(out) => {
                let result = serde_json::json!({
                    "index": out.index,
                    "deposit_pubkey": out.deposit_pubkey_hex,
                    "deposit_id": out.deposit_id_hex,
                    "ledger_id": out.ledger_id,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (false, None, Some(e)),
        }
    }

    /// Admin: concise node + per-ledger status for the hub control plane.
    /// Admin-gated (operator's own key or the configured hub `admin.npub`),
    /// read-only. Returns operator identity, network, chain tip, wallet
    /// balance, and a per-ledger summary.
    pub(crate) async fn process_admin_status_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        let (xo, _) = self.node_id.x_only_public_key();
        let chain_tip = self.wallet.get_block_height().unwrap_or(0);
        let wallet_balance = self.wallet_balance().unwrap_or(0);

        let ledgers: Vec<serde_json::Value> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .values()
                .map(|arc| {
                    let l = arc.read().unwrap();
                    serde_json::json!({
                        "ledger_id": l.ledger_id_hex(),
                        "role": format!("{:?}", l.role),
                        "quorum_active":
                            l.state.quorum_state == deposits_core::QuorumState::Active,
                        "quorum_size": l.state.quorum_members.len(),
                        "reserves_sats": l.reserves_amount() / 1000,
                        "collateral_sats": l.state.collateral_amount / 1000,
                        "updates": l.history.len(),
                    })
                })
                .collect()
        };

        let result = serde_json::json!({
            "operator": hex::encode(xo.serialize()),
            "network": format!("{:?}", self.wallet.network()),
            "chain_tip": chain_tip,
            "wallet_balance_sats": wallet_balance,
            "ledgers": ledgers,
        });
        (true, Some(result.to_string()), None)
    }

    /// Admin: drop an unfunded, PreQuorum ledger this node operates — for
    /// clearing orphan ledgers left by a messy bring-up.
    ///
    /// Hard-refuses anything that could hold value. To be dropped a ledger
    /// must be: Operator-role (partner replicas re-sync on their own and aren't
    /// ours to delete), PreQuorum (never Active/funded), with no recorded
    /// taproot vault, zero reserves/collateral, and — unless `force` — a synced
    /// zero-balance ledger wallet (so funds sent to the deposit address but not
    /// yet activated aren't silently orphaned). Removes it from memory
    /// (handler, actor, wallet) before deleting its on-disk jsonl + wallet dir,
    /// so nothing re-persists it. Irreversible, but only ever for an empty
    /// ledger.
    pub(crate) async fn process_ledger_drop_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let ledger_id = request
            .params
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or(request.ledger_id.as_str())
            .to_string();
        let force = request
            .params
            .get("force")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let short = &ledger_id[..16.min(ledger_id.len())];
        let refuse = |msg: String| (false, None, Some(msg));

        // Role + state snapshot under the ledgers lock.
        let (role_operator, prequorum, reserves, collateral) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let Some(arc) = ledgers.get(&ledger_id) else {
                return refuse(format!("ledger {} not found on this node", short));
            };
            let l = arc.read().unwrap();
            (
                matches!(l.role, deposits_core::ledger::LedgerRole::Operator),
                l.state.quorum_state == deposits_core::QuorumState::PreQuorum,
                l.reserves_amount(),
                l.state.collateral_amount,
            )
        };
        if !role_operator {
            return refuse(
                "refusing: this node is not the Operator of that ledger (partner replicas \
                 re-sync on their own and aren't dropped here)"
                    .to_string(),
            );
        }
        if !prequorum {
            return refuse(
                "refusing: ledger quorum is not PreQuorum — active/funded ledgers are never \
                 dropped"
                    .to_string(),
            );
        }
        if reserves != 0 || collateral != 0 {
            return refuse(format!(
                "refusing: ledger carries reserves={} / collateral={} msats",
                reserves, collateral
            ));
        }

        // Load the per-ledger wallet without creating a fresh account: use the
        // cached one, else load from disk only if its dir exists.
        let lw = {
            let cached = self.ledger_wallets.read().unwrap().get(&ledger_id).cloned();
            match cached {
                Some(w) => Some(w),
                None => {
                    let dir = crate::ledger_wallet::LedgerWallet::ledger_dir(
                        &self.data_dir,
                        &ledger_id,
                    );
                    if dir.join("account_index.txt").exists() {
                        match self.ensure_ledger_wallet(&ledger_id) {
                            Ok(w) => Some(w),
                            Err(e) => {
                                return refuse(format!("could not load ledger wallet: {}", e))
                            }
                        }
                    } else {
                        None
                    }
                }
            }
        };
        if let Some(lw) = &lw {
            if lw.taproot_reserves().is_some() {
                return refuse(
                    "refusing: an on-chain taproot vault is recorded for this ledger".to_string(),
                );
            }
            if !force {
                if let Err(e) = lw.sync() {
                    return refuse(format!(
                        "refusing: couldn't sync the ledger wallet to confirm it's empty: {} \
                         (pass force=true to skip the on-chain check)",
                        e
                    ));
                }
                match lw.balance_sats() {
                    Ok(0) => {}
                    Ok(bal) => {
                        return refuse(format!(
                            "refusing: ledger wallet holds {} sats — withdraw/sweep before \
                             dropping",
                            bal
                        ))
                    }
                    Err(e) => {
                        return refuse(format!("refusing: couldn't read ledger balance: {}", e))
                    }
                }
            }
        }

        // Gate passed. Drop from memory first (so no save re-persists it),
        // then delete on-disk state. Removing the actor handle closes its inbox
        // → the actor task exits.
        self.handler.ledgers.lock().unwrap().remove(&ledger_id);
        self.ledger_actors.lock().unwrap().remove(&ledger_id);
        self.ledger_wallets.write().unwrap().remove(&ledger_id);

        let jsonl = self
            .data_dir
            .join("wallet")
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let dir = crate::ledger_wallet::LedgerWallet::ledger_dir(&self.data_dir, &ledger_id);
        let _ = std::fs::remove_file(&jsonl);
        let _ = std::fs::remove_dir_all(&dir);

        tracing::info!("Dropped unfunded PreQuorum ledger {}", short);
        (
            true,
            Some(serde_json::json!({ "dropped": ledger_id }).to_string()),
            None,
        )
    }

    /// Admin: report the currently-published Kind-39100 advertisement terms for
    /// each operator ledger (read-only). Fetches from the relay — the source of
    /// truth for the static terms (republish refreshes the dynamic fields).
    pub(crate) async fn process_advertise_status_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let ledger_ids: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .values()
                .filter_map(|arc| {
                    let l = arc.read().unwrap();
                    matches!(l.role, deposits_core::ledger::LedgerRole::Operator)
                        .then(|| l.ledger_id_hex())
                })
                .collect()
        };
        let mut ads = Vec::new();
        for lid in ledger_ids {
            match self.nostr.fetch_ledger_advertisement(&lid).await {
                Ok(Some(ad)) => ads.push(serde_json::json!({
                    "ledger_id": lid,
                    "advertised": true,
                    "operator_name": ad.operator_name,
                    "description": ad.description,
                    "annual_fee_bps": ad.annual_fee_bps,
                    "deposit_fee_bps": ad.deposit_fee_bps,
                    "withdrawal_fee_bps": ad.withdrawal_fee_bps,
                    "invoice_fee_bps": ad.invoice_fee_bps,
                    "max_deposit_msats": ad.max_deposit_msats,
                    "min_deposit_msats": ad.min_deposit_msats,
                })),
                _ => ads.push(serde_json::json!({ "ledger_id": lid, "advertised": false })),
            }
        }
        (true, Some(serde_json::json!({ "ads": ads }).to_string()), None)
    }

    /// Admin: set advertisement terms (operator name/description, fee bps,
    /// deposit limits) for one ledger and republish the Kind-39100 ad.
    /// Gated to an Operator-role, quorum-Active ledger (advertising a
    /// quorumless ledger invites deposits with no custody guarantee). Fetches
    /// the existing ad as the base (preserving fields not overridden); if none
    /// exists yet, builds a fresh one from current ledger state.
    pub(crate) async fn process_advertise_set_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let p = &request.params;
        let refuse = |m: String| (false, None, Some(m));
        let ledger_id = p
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if ledger_id.is_empty() {
            return refuse("ledger_id is required".to_string());
        }

        // Gate: Operator role + active quorum.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&ledger_id) {
                None => return refuse(format!("ledger {} not found", &ledger_id[..16.min(ledger_id.len())])),
                Some(arc) => {
                    let l = arc.read().unwrap();
                    if !matches!(l.role, deposits_core::ledger::LedgerRole::Operator) {
                        return refuse("not the operator of this ledger".to_string());
                    }
                    if l.state.quorum_state != deposits_core::QuorumState::Active {
                        return refuse(
                            "ledger quorum is not active — can't advertise a quorumless ledger"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Base ad: existing (preserve untouched fields) or a fresh build.
        let mut ad = match self.nostr.fetch_ledger_advertisement(&ledger_id).await {
            Ok(Some(a)) => a,
            _ => {
                let Some((_, l)) = self.get_ledger_with_id(&ledger_id) else {
                    return refuse("ledger not found".to_string());
                };
                let network_str = match self.wallet.network() {
                    bitcoin::Network::Bitcoin => "bitcoin",
                    bitcoin::Network::Testnet => "testnet",
                    bitcoin::Network::Signet => "signet",
                    bitcoin::Network::Regtest => "regtest",
                    _ => "unknown",
                };
                let mut fresh = crate::nostr::LedgerAdvertisement::new(
                    l.ledger_id_hex(),
                    hex::encode(l.operator_key().serialize()),
                    l.reserves_key().to_string(),
                    network_str.to_string(),
                );
                fresh.guarantees = crate::nostr::LedgerAdvertisement::default_guarantees();
                fresh.capabilities = crate::operator_policy::default_advertised_capabilities();
                fresh.reserves_amount_msats = l.reserves_amount();
                fresh.collateral_amount_msats = l.state.collateral_amount;
                fresh.current_block = l
                    .history
                    .last()
                    .map(|u| u.block_height)
                    .unwrap_or_else(|| self.wallet.get_block_height().unwrap_or(0));
                fresh.quorum_state = format!("{:?}", l.state.quorum_state);
                fresh.quorum_members = l
                    .state
                    .quorum_members
                    .iter()
                    .map(|m| m.pubkey.to_string())
                    .collect();
                fresh
            }
        };

        // Apply operator overrides.
        if let Some(v) = p.get("operator_name").and_then(|v| v.as_str()) {
            ad.operator_name = Some(v.to_string());
        }
        if let Some(v) = p.get("description").and_then(|v| v.as_str()) {
            ad.description = Some(v.to_string());
        }
        if let Some(v) = p.get("annual_fee_bps").and_then(|v| v.as_u64()) {
            ad.annual_fee_bps = v as u32;
        }
        if let Some(v) = p.get("annualized_fixed_msats").and_then(|v| v.as_u64()) {
            ad.annualized_fixed_msats = v;
        }
        if let Some(v) = p.get("deposit_fee_bps").and_then(|v| v.as_u64()) {
            ad.deposit_fee_bps = v as u32;
        }
        if let Some(v) = p.get("withdrawal_fee_bps").and_then(|v| v.as_u64()) {
            ad.withdrawal_fee_bps = v as u32;
        }
        if let Some(v) = p.get("invoice_fee_bps").and_then(|v| v.as_u64()) {
            ad.invoice_fee_bps = v as u32;
        }
        if let Some(v) = p.get("max_deposit_msats").and_then(|v| v.as_u64()) {
            ad.max_deposit_msats = v;
        }
        if let Some(v) = p.get("min_deposit_msats").and_then(|v| v.as_u64()) {
            ad.min_deposit_msats = v;
        }

        match self.nostr.publish_ledger_advertisement(&ad).await {
            Ok(_) => (
                true,
                Some(serde_json::json!({ "ledger_id": ledger_id, "advertised": true }).to_string()),
                None,
            ),
            Err(e) => refuse(format!("publish advertisement: {}", e)),
        }
    }

    /// Admin: retract this node's Kind-39100 ad for a ledger (NIP-09 deletion).
    ///
    /// Gated to Operator role but allowed in ANY quorum state — an operator may
    /// retract a pre-quorum, stale, or simply-unwanted ad. Best-effort: relays
    /// that honor NIP-09 drop the ad; others may keep serving it (that's Nostr).
    pub(crate) async fn process_advertise_retract_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let refuse = |m: String| (false, None, Some(m));
        let ledger_id = request
            .params
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if ledger_id.is_empty() {
            return refuse("ledger_id is required".to_string());
        }
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&ledger_id) {
                None => {
                    return refuse(format!(
                        "ledger {} not found",
                        &ledger_id[..16.min(ledger_id.len())]
                    ))
                }
                Some(arc) => {
                    if !matches!(
                        arc.read().unwrap().role,
                        deposits_core::ledger::LedgerRole::Operator
                    ) {
                        return refuse("not the operator of this ledger".to_string());
                    }
                }
            }
        }
        match self.nostr.delete_ledger_advertisement(&ledger_id).await {
            Ok(event_id) => (
                true,
                Some(
                    serde_json::json!({
                        "ledger_id": ledger_id,
                        "advertised": false,
                        "deletion_event": event_id,
                    })
                    .to_string(),
                ),
                None,
            ),
            Err(e) => refuse(format!("retract advertisement: {}", e)),
        }
    }

    /// Admin: rebuild a ledger's ad from operator_policy.json (or the project
    /// defaults when a field is unset) and republish.
    ///
    /// Unlike `advertise_set` — which preserves the on-relay ad and overrides
    /// only the fields passed — `refresh` re-derives every operator-settable
    /// field from policy. This is how an operator pushes the default
    /// 2%/yr + 120 sat/yr custody fee onto an ad that was first published with
    /// zeros (the on-relay ad's stale fees would otherwise be preserved).
    /// Gated Operator + active quorum.
    pub(crate) async fn process_advertise_refresh_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let refuse = |m: String| (false, None, Some(m));
        let ledger_id = request
            .params
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if ledger_id.is_empty() {
            return refuse("ledger_id is required".to_string());
        }
        let Some((_, l)) = self.get_ledger_with_id(&ledger_id) else {
            return refuse("ledger not found".to_string());
        };
        if !matches!(l.role, deposits_core::ledger::LedgerRole::Operator) {
            return refuse("not the operator of this ledger".to_string());
        }
        if l.state.quorum_state != deposits_core::QuorumState::Active {
            return refuse(
                "ledger quorum is not active — can't advertise a quorumless ledger".to_string(),
            );
        }
        let network_str = match self.wallet.network() {
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
            _ => "unknown",
        };
        let mut ad = crate::nostr::LedgerAdvertisement::new(
            l.ledger_id_hex(),
            hex::encode(l.operator_key().serialize()),
            l.reserves_key().to_string(),
            network_str.to_string(),
        );
        ad.guarantees = crate::nostr::LedgerAdvertisement::default_guarantees();
        ad.capabilities = crate::operator_policy::default_advertised_capabilities();
        ad.reserves_amount_msats = l.reserves_amount();
        ad.collateral_amount_msats = l.state.collateral_amount;
        ad.current_block = l
            .history
            .last()
            .map(|u| u.block_height)
            .unwrap_or_else(|| self.wallet.get_block_height().unwrap_or(0));
        ad.quorum_state = format!("{:?}", l.state.quorum_state);
        ad.quorum_members = l
            .state
            .quorum_members
            .iter()
            .map(|m| m.pubkey.to_string())
            .collect();
        ad.max_deposit_balance_msats = self.max_deposit_balance_msats();

        // Re-derive operator-settable fields from policy (defaults when unset).
        let policy = crate::operator_policy::OperatorPolicy::load(&self.data_dir)
            .ok()
            .flatten()
            .unwrap_or_default();
        ad.annual_fee_bps = policy.effective_annual_fee_bps();
        ad.annualized_fixed_msats = policy.effective_annualized_fixed_msats();
        ad.fee_period_blocks = policy.fee_period_blocks.unwrap_or(2016);
        ad.deposit_fee_bps = policy.deposit_fee_bps.unwrap_or(0);
        ad.withdrawal_fee_bps = policy.withdrawal_fee_bps.unwrap_or(0);
        ad.invoice_fee_bps = policy.invoice_fee_bps.unwrap_or(0);
        if let Some(v) = policy.max_deposit_msats {
            ad.max_deposit_msats = v;
        }
        if let Some(v) = policy.min_deposit_msats {
            ad.min_deposit_msats = v;
        }
        if policy.operator_name.is_some() {
            ad.operator_name = policy.operator_name.clone();
        } else if let Some(n) = self.operator_name() {
            ad.operator_name = Some(n.to_string());
        }
        if policy.description.is_some() {
            ad.description = policy.description.clone();
        }

        match self.nostr.publish_ledger_advertisement(&ad).await {
            Ok(_) => (
                true,
                Some(
                    serde_json::json!({
                        "ledger_id": ledger_id,
                        "advertised": true,
                        "annual_fee_bps": ad.annual_fee_bps,
                        "annualized_fixed_msats": ad.annualized_fixed_msats,
                    })
                    .to_string(),
                ),
                None,
            ),
            Err(e) => refuse(format!("publish advertisement: {}", e)),
        }
    }

    /// Admin: list this node's liquidity-drip plans (read-only).
    pub(crate) async fn process_liquidity_list_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        match crate::operator_drips::DripRegistry::load(&self.data_dir) {
            Ok(reg) => {
                let plans = serde_json::to_value(&reg.plans).unwrap_or(serde_json::json!([]));
                (true, Some(serde_json::json!({ "plans": plans }).to_string()), None)
            }
            Err(e) => (false, None, Some(format!("load drips: {}", e))),
        }
    }

    /// Admin: create a liquidity-drip plan. Mirrors `deposits-node liquidity
    /// drip-create` but, since it runs on the daemon, also fail-fast validates
    /// the target ledger is one this node operates and whose quorum is active
    /// (a drip opens self-deposits on it). The running daemon's auto-task picks
    /// the plan up on its next cycle.
    pub(crate) async fn process_liquidity_create_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let p = &request.params;
        let refuse = |m: String| (false, None, Some(m));
        let alias = p.get("alias").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ledger_id = p.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let initial = p.get("initial_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let decrement = p.get("decrement_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let interval = p.get("interval_sec").and_then(|v| v.as_u64()).unwrap_or(0);
        let fuzz = p.get("interval_fuzz_sec").and_then(|v| v.as_u64()).unwrap_or(0);

        if alias.is_empty() || ledger_id.is_empty() {
            return refuse("alias and ledger_id are required".to_string());
        }
        if initial == 0 || decrement == 0 || interval == 0 {
            return refuse(
                "initial_sats, decrement_sats, interval_sec must all be > 0".to_string(),
            );
        }
        if decrement > initial {
            return refuse(format!(
                "decrement_sats ({}) must not exceed initial_sats ({})",
                decrement, initial
            ));
        }
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&ledger_id) {
                None => {
                    return refuse(format!(
                        "ledger {} not found on this node",
                        &ledger_id[..16.min(ledger_id.len())]
                    ))
                }
                Some(arc) => {
                    let l = arc.read().unwrap();
                    if !matches!(l.role, deposits_core::ledger::LedgerRole::Operator) {
                        return refuse("ledger is not operated by this node".to_string());
                    }
                    if l.state.quorum_state != deposits_core::QuorumState::Active {
                        return refuse(
                            "ledger quorum is not active — fund + begin the quorum before \
                             adding a liquidity drip"
                                .to_string(),
                        );
                    }
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let plan = crate::operator_drips::DripPlan {
            alias: alias.clone(),
            ledger_id,
            target_deposit_sats: initial,
            decrement_sats: decrement,
            interval_sec: interval,
            interval_fuzz_sec: fuzz,
            buffer_index: None,
            paused: false,
            created_unix: now,
            last_tick_unix: 0,
            next_tick_unix: 0,
            ticks_completed: 0,
        };
        let mut reg = match crate::operator_drips::DripRegistry::load(&self.data_dir) {
            Ok(r) => r,
            Err(e) => return refuse(format!("load drips: {}", e)),
        };
        if let Err(e) = reg.insert(plan) {
            return refuse(e);
        }
        if let Err(e) = reg.save(&self.data_dir) {
            return refuse(format!("save drips: {}", e));
        }
        (true, Some(serde_json::json!({ "created": alias }).to_string()), None)
    }

    /// Admin: pause/resume a drip plan by alias (the auto-task skips paused
    /// plans). `paused` selects which.
    pub(crate) async fn process_liquidity_set_paused_request(
        &self,
        request: &crate::nostr::LedgerRequest,
        paused: bool,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let alias = request
            .params
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if alias.is_empty() {
            return (false, None, Some("alias is required".to_string()));
        }
        let mut reg = match crate::operator_drips::DripRegistry::load(&self.data_dir) {
            Ok(r) => r,
            Err(e) => return (false, None, Some(format!("load drips: {}", e))),
        };
        match reg.find_mut(&alias) {
            Some(plan) => plan.paused = paused,
            None => return (false, None, Some(format!("no drip plan '{}'", alias))),
        }
        if let Err(e) = reg.save(&self.data_dir) {
            return (false, None, Some(format!("save drips: {}", e)));
        }
        (
            true,
            Some(serde_json::json!({ "alias": alias, "paused": paused }).to_string()),
            None,
        )
    }

    /// Admin: remove a drip plan by alias (the underlying buffer deposit, if
    /// any, is left untouched on the ledger).
    pub(crate) async fn process_liquidity_remove_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let alias = request
            .params
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if alias.is_empty() {
            return (false, None, Some("alias is required".to_string()));
        }
        let mut reg = match crate::operator_drips::DripRegistry::load(&self.data_dir) {
            Ok(r) => r,
            Err(e) => return (false, None, Some(format!("load drips: {}", e))),
        };
        if reg.remove(&alias).is_none() {
            return (false, None, Some(format!("no drip plan '{}'", alias)));
        }
        if let Err(e) = reg.save(&self.data_dir) {
            return (false, None, Some(format!("save drips: {}", e)));
        }
        (true, Some(serde_json::json!({ "removed": alias }).to_string()), None)
    }

    /// Admin: increase a buffer deposit's balance via a synthetic
    /// InvoiceCredit. The `invoice_id` is a random UUID-like string —
    /// co-signers don't care where the payment came from, they validate
    /// the operator's signed ledger update against the reserves
    /// invariant. No Lightning payment actually happens.
    pub(crate) async fn process_admin_buffer_fill_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let Some(index) = request.params.get("index").and_then(|v| v.as_u64()) else {
            return (false, None, Some("missing `index`".into()));
        };
        let Some(amount_msats) = request.params.get("amount_msats").and_then(|v| v.as_u64()) else {
            return (false, None, Some("missing `amount_msats`".into()));
        };
        match self.internal_buffer_fill(index as u32, amount_msats).await {
            Ok(new_balance) => {
                let result = serde_json::json!({
                    "index": index,
                    "new_balance_msats": new_balance,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (false, None, Some(e)),
        }
    }

    /// Admin: decrease a buffer deposit's balance via a synthetic
    /// InvoiceLock + InvoiceFulfill pair. Daemon generates the preimage,
    /// signs the lock authorization with the deposit's derived key, and
    /// records both ops. Co-signers verify:
    ///   - lock witness matches the deposit's descriptor (operator holds
    ///     the derived key, so this passes);
    ///   - SHA256(preimage) == payment_hash stored at lock time.
    /// Everything the protocol requires for a real Lightning payment is
    /// satisfied; what it doesn't check — whether Lightning actually
    /// moved sats — doesn't apply here, and co-signers have no way to
    /// tell the difference.
    pub(crate) async fn process_admin_buffer_drain_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }
        let Some(index) = request.params.get("index").and_then(|v| v.as_u64()) else {
            return (false, None, Some("missing `index`".into()));
        };
        let Some(amount_msats) = request.params.get("amount_msats").and_then(|v| v.as_u64()) else {
            return (false, None, Some("missing `amount_msats`".into()));
        };
        match self.internal_buffer_drain(index as u32, amount_msats).await {
            Ok(new_balance) => {
                let result = serde_json::json!({
                    "index": index,
                    "new_balance_msats": new_balance,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (false, None, Some(e)),
        }
    }

    /// Admin: list all buffer deposits the operator has opened (index,
    /// pubkey, deposit_id, current balance on the ledger).
    pub(crate) async fn process_admin_buffer_list_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        if let Err(denial) = self.check_admin_authorized(request) {
            return denial;
        }

        let entries = self.load_buffer_indices();
        let ledgers = self.handler.ledgers.lock().unwrap();

        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let descriptor = format!("pk({})", entry.deposit_pubkey);
            let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
            let (balance, locked) = ledgers
                .get(&entry.ledger_id)
                .and_then(|arc| {
                    let l = arc.read().unwrap();
                    l.state
                        .deposits
                        .get(&deposit_id)
                        .map(|d| (d.balance, d.locked_balance))
                })
                .unwrap_or((0, 0));
            out.push(serde_json::json!({
                "index": entry.index,
                "ledger_id": entry.ledger_id,
                "deposit_pubkey": entry.deposit_pubkey,
                "deposit_id": hex::encode(deposit_id),
                "balance_msats": balance,
                "locked_msats": locked,
            }));
        }
        drop(ledgers);

        let result = serde_json::json!({ "buffers": out });
        (true, Some(result.to_string()), None)
    }

}
