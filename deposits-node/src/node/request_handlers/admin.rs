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

        self.lock_invoice_payment(
            &entry.ledger_id,
            deposit_id,
            amount_msats,
            payment_id,
            op_nonce,
            op_expiry,
            lock_witness,
        )
        .await
        .map_err(|e| format!("lock_invoice_payment: {}", e))?;
        self.fulfill_invoice_payment(
            &entry.ledger_id,
            deposit_id,
            amount_msats,
            payment_id,
            preimage,
            fulfill_witness,
        )
        .await
        .map_err(|e| format!("fulfill_invoice_payment: {}", e))
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
