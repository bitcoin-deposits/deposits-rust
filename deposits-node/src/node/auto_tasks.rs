use super::*;

impl Node {
    // Auto-Response Tasks
    // ========================================================================

    /// Auto-complete deposits that have been funded on-chain
    pub async fn auto_complete_deposits(&self) {
        use deposits_core::types::DepositOfferStatus;

        let offers = self.list_deposit_offers();
        let pending: Vec<_> = offers
            .iter()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .collect();

        if pending.is_empty() {
            return;
        }

        // Sync wallet ONCE before checking all offers (not per-offer)
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed in auto_complete_deposits: {}", e);
            return;
        }

        for (offer, _) in pending {
            let offer_id = offer.offer_id;

            // Skip offers for ledgers we don't operate.
            // Quorum members also load the ledger, but only the operator should
            // auto-complete deposits — otherwise multiple daemons race to write
            // the same sequence number and cause hash chain breaks.
            if !self.is_operator_of_ledger(&offer.ledger_id) {
                continue;
            }

            // Check if funded (skip_sync=true since we synced above)
            match self.check_deposit_offer_funding_inner(&offer_id, true) {
                Ok(Some((txid, amount_sats))) => {
                    tracing::info!(
                        "Auto-completing funded deposit: offer={}... txid={}... amount={} sats",
                        hex::encode(&offer_id[..8]),
                        &txid[..16.min(txid.len())],
                        amount_sats
                    );

                    // Complete the deposit with co-signing
                    match self
                        .complete_deposit_offer(&offer_id, txid.clone(), amount_sats)
                        .await
                    {
                        Ok(new_balance) => {
                            tracing::info!("Deposit completed! New balance: {} msats", new_balance);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to complete deposit {}...: {}",
                                hex::encode(&offer_id[..8]),
                                e
                            );
                        }
                    }
                }
                Ok(None) => {
                    // Not funded yet, skip
                }
                Err(e) => {
                    tracing::debug!(
                        "Error checking deposit funding {}...: {}",
                        hex::encode(&offer_id[..8]),
                        e
                    );
                }
            }
        }
    }

    /// Auto-complete locked withdrawals by broadcasting their transactions
    pub async fn auto_complete_withdrawals(&self) {
        // Get all locked withdrawals
        let locked_withdrawals: Vec<([u8; 32], OnChainWithdrawal)> = {
            let withdrawals = self.withdrawals.lock().unwrap();
            withdrawals
                .iter()
                .filter_map(|(id, (w, status))| {
                    if matches!(status, OnChainWithdrawalStatus::Locked { .. }) {
                        Some((*id, w.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        if locked_withdrawals.is_empty() {
            return;
        }

        for (withdrawal_id, withdrawal) in locked_withdrawals {
            // Find the ledger for this withdrawal
            let ledger_id = {
                let ledgers = match self.handler.ledgers.try_lock() {
                    Ok(l) => l,
                    Err(_) => {
                        tracing::warn!(
                            "auto_complete_withdrawals: ledgers lock contended, skipping"
                        );
                        return;
                    }
                };
                let mut found_id = None;
                for (lid, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    // Check if this ledger is operated by us
                    if ledger.operator_key() != self.node_id {
                        continue;
                    }
                    // Check if this ledger has the withdrawal's deposit
                    if ledger.state.deposits.contains_key(&withdrawal.deposit_id) {
                        found_id = Some(lid.clone());
                        break;
                    }
                }
                found_id
            };

            let Some(ledger_id) = ledger_id else {
                tracing::debug!(
                    "Could not find ledger for withdrawal {}...",
                    hex::encode(&withdrawal_id[..8])
                );
                continue;
            };

            tracing::info!(
                "Auto-completing locked withdrawal: id={}... to {} for {} sats",
                hex::encode(&withdrawal_id[..8]),
                &withdrawal.destination_address[..20.min(withdrawal.destination_address.len())],
                withdrawal.amount_sats
            );

            match self.complete_withdrawal(&ledger_id, &withdrawal_id).await {
                Ok(result) => {
                    tracing::info!(
                        "Withdrawal completed! txid={}, final balance={} msats",
                        &result.txid[..16.min(result.txid.len())],
                        result.final_balance_msats
                    );
                    // Sync wallet after each successful broadcast to update UTXO set
                    // This prevents subsequent withdrawals from trying to spend already-used UTXOs
                    if let Err(e) = self.sync_wallet() {
                        tracing::warn!("Wallet sync after withdrawal failed: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to complete withdrawal {}...: {}",
                        hex::encode(&withdrawal_id[..8]),
                        e
                    );
                }
            }
        }
    }

    /// Auto-collect fees from deposits when due
    ///
    /// This checks all operated ledgers for deposits that have fees due (based on
    /// block height and fee collection frequency) and applies FeeCollect operations.
    pub async fn auto_collect_fees(&self) {
        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Failed to get block height for fee collection: {}", e);
                return;
            }
        };

        let _block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Get operated ledgers (where we are the operator)
        // Use try_lock to avoid blocking the tokio thread if a detached JoinSet task holds the mutex
        let ledgers = match self.handler.ledgers.try_lock() {
            Ok(l) => l.clone(),
            Err(_) => {
                tracing::warn!("auto_collect_fees: ledgers lock contended, skipping this cycle");
                return;
            }
        };
        let operated: Vec<_> = ledgers
            .into_iter()
            .filter(|(_, arc)| arc.read().unwrap().operator_key() == self.node_id)
            .collect();

        for (ledger_id, ledger_arc) in operated {
            // Collect fees that are due
            let fee_ops: Vec<(DepositId, u64)> = {
                let ledger = ledger_arc.read().unwrap();
                ledger
                    .state
                    .deposits
                    .iter()
                    .filter_map(|(deposit_id, deposit)| {
                        let fee = deposit.calculate_fees_due(current_block);
                        let available = deposit.balance.saturating_sub(deposit.locked_balance);
                        if fee > 0 && fee <= available {
                            Some((*deposit_id, fee))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            if fee_ops.is_empty() {
                continue;
            }

            // Commit each FeeCollect operation via the staged flow
            for (deposit_id, amount) in fee_ops {
                tracing::info!(
                    "Collecting fee: deposit={}... amount={} sats",
                    hex::encode(&deposit_id[..8]),
                    amount / 1000
                );

                let operation = LedgerOperation::FeeCollect {
                    deposit_id,
                    amount,
                    block_height: current_block,
                };

                if let Err(e) = self.commit_operation(&ledger_id, operation).await {
                    tracing::warn!(
                        "Failed to collect fee from deposit {}...: {}",
                        hex::encode(&deposit_id[..8]),
                        e
                    );
                    continue;
                }
            }
        }
    }

    /// Automatically timeout expired transfers.
    ///
    /// Scans all operated ledgers for pending transfers that have passed their
    /// timeout_height and issues TransferFail operations to return funds
    /// to the source deposits.
    pub async fn auto_timeout_transfers(&self) {
        use deposits_core::messages::LedgerOperation;

        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Failed to get block height for transfer timeout: {}", e);
                return;
            }
        };

        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Get operated ledgers (where we are the operator)
        let ledgers = match self.handler.ledgers.try_lock() {
            Ok(l) => l.clone(),
            Err(_) => {
                tracing::warn!(
                    "auto_timeout_transfers: ledgers lock contended, skipping this cycle"
                );
                return;
            }
        };
        let operated: Vec<_> = ledgers
            .into_iter()
            .filter(|(_, arc)| arc.read().unwrap().operator_key() == self.node_id)
            .collect();

        for (ledger_id, ledger_arc) in operated {
            // Find expired transfers
            let expired_transfers: Vec<[u8; 32]> = {
                let ledger = ledger_arc.read().unwrap();
                ledger
                    .state
                    .pending_transfers
                    .iter()
                    .filter(|(_, pending)| current_block >= pending.timeout_height)
                    .map(|(id, _)| *id)
                    .collect()
            };

            if expired_transfers.is_empty() {
                continue;
            }

            // Process only ONE timeout per periodic cycle. Timeouts are low priority
            // and each is a full ledger operation (append + sign + persist + broadcast).
            // Processing them in a batch starves transfer_lock/transfer_complete handling.
            // The next periodic cycle (5s) will pick up more.
            if let Some(&transfer_id) = expired_transfers.first() {
                // Re-check that the transfer is still pending (a complete may
                // have arrived since we collected the list)
                {
                    let ledger = ledger_arc.read().unwrap();
                    if !ledger.state.pending_transfers.contains_key(&transfer_id) {
                        continue;
                    }
                }

                if expired_transfers.len() > 1 {
                    tracing::info!(
                        "Processing 1 of {} expired transfers (rest deferred to next cycle)",
                        expired_transfers.len()
                    );
                }

                tracing::info!(
                    "Timing out expired transfer: {}... (block {} >= timeout)",
                    hex::encode(&transfer_id[..8]),
                    current_block
                );

                let operation = LedgerOperation::TransferFail {
                    transfer_id,
                    block_hash,
                    reason: 1,
                };

                if let Err(e) = self.commit_operation(&ledger_id, operation).await {
                    tracing::warn!(
                        "Failed to timeout transfer {}...: {}",
                        hex::encode(&transfer_id[..8]),
                        e
                    );
                    continue;
                }

                tracing::info!(
                    "Transfer {} timed out, funds returned to source",
                    hex::encode(&transfer_id[..8])
                );
            }
        }
    }

    /// Automatically credit deposits when Lightning invoices are paid.
    ///
    /// This polls the Lightning backend for payment status and creates
    /// InvoiceCredit operations for any pending invoices that have been
    /// successfully paid.
    pub async fn auto_credit_received_payments(&self) {
        use crate::lightning_backend::PaymentStatus;

        // Get pending invoices
        let pending: Vec<([u8; 32], PendingInvoice)> = {
            self.pending_invoices
                .lock()
                .unwrap()
                .iter()
                .map(|(h, p)| (*h, p.clone()))
                .collect()
        };

        if pending.is_empty() {
            return;
        }

        tracing::info!("auto_credit: checking {} pending invoice(s)", pending.len());

        // Query the Lightning backend for payment status
        let cli = crate::lightning_backend::from_env();
        let payments = match cli.list_payments() {
            Ok(payments) => {
                tracing::info!(
                    "auto_credit: Lightning backend returned {} payments",
                    payments.len()
                );
                payments
            }
            Err(e) => {
                tracing::warn!("auto_credit: Failed to list payments: {}", e);
                return;
            }
        };

        // Check each pending invoice against payments
        for (payment_hash, invoice) in pending {
            let payment_hash_hex = hex::encode(payment_hash);

            // Find matching payment by ID (payment hash)
            let matching_payment = payments.iter().find(|p| p.id == payment_hash_hex);

            if let Some(payment) = matching_payment {
                match payment.status {
                    PaymentStatus::Succeeded => {
                        // Payment succeeded - credit the deposit
                        tracing::info!(
                            "Invoice paid! Crediting deposit {}... with {} msat (hash: {}...)",
                            hex::encode(&invoice.deposit_id[..8]),
                            invoice.amount_msat,
                            &payment_hash_hex[..16]
                        );

                        // Generate invoice_id from the invoice string
                        let invoice_id = format!(
                            "bolt11:{}",
                            &invoice.invoice[..32.min(invoice.invoice.len())]
                        );

                        match self
                            .credit_deposit(
                                &invoice.ledger_id,
                                invoice.deposit_id,
                                invoice.amount_msat,
                                payment_hash,
                                invoice_id,
                            )
                            .await
                        {
                            Ok(new_balance) => {
                                tracing::info!(
                                    "Deposit credited! New balance: {} msat",
                                    new_balance
                                );
                                // Remove from pending and persist
                                self.pending_invoices.lock().unwrap().remove(&payment_hash);
                                self.save_pending_invoices();
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to credit deposit for invoice {}...: {}",
                                    &payment_hash_hex[..16],
                                    e
                                );
                            }
                        }
                    }
                    PaymentStatus::Failed => {
                        // Payment failed - remove from pending (invoice expired or rejected)
                        tracing::warn!(
                            "Invoice {}... payment failed, removing from pending",
                            &payment_hash_hex[..16]
                        );
                        self.pending_invoices.lock().unwrap().remove(&payment_hash);
                    }
                    PaymentStatus::Pending => {
                        // Still pending, do nothing
                    }
                }
            }

            // Clean up old invoices (older than 1 hour)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > invoice.created_at + 3600 {
                tracing::debug!(
                    "Removing expired pending invoice {}...",
                    &payment_hash_hex[..16]
                );
                self.pending_invoices.lock().unwrap().remove(&payment_hash);
            }
        }

        // Persist after any changes
        self.save_pending_invoices();
    }

    /// Resolve open outbound invoice locks by checking the Lightning
    /// backend's payment status.
    ///
    /// Scans all owned ledgers for open_invoice_locks. For each, queries
    /// the backend for the payment status and commits InvoiceFulfill (if
    /// succeeded) or InvoiceFail (if failed). Pending payments are left alone.
    pub async fn auto_complete_outbound_payments(&self) {
        use crate::lightning_backend::PaymentStatus;

        // Collect open locks from all owned ledgers
        let mut open_locks: Vec<(String, [u8; 32], deposits_core::types::OpenInvoiceLock)> =
            Vec::new();
        {
            let ledgers = match self.handler.ledgers.try_lock() {
                Ok(l) => l,
                Err(_) => {
                    tracing::warn!(
                        "auto_complete_outbound_payments: ledgers lock contended, skipping"
                    );
                    return;
                }
            };
            for (lid, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();
                for (payment_id, lock) in &ledger.state.open_invoice_locks {
                    open_locks.push((lid.clone(), *payment_id, lock.clone()));
                }
            }
        }

        if open_locks.is_empty() {
            return;
        }

        tracing::info!(
            "auto_complete_outbound: checking {} open invoice lock(s)",
            open_locks.len()
        );

        let cli = crate::lightning_backend::from_env();
        let payments = match cli.list_payments() {
            Ok(payments) => payments,
            Err(e) => {
                tracing::warn!("auto_complete_outbound: failed to list payments: {}", e);
                return;
            }
        };

        for (ledger_id, payment_id, lock) in open_locks {
            let payment_hex = hex::encode(payment_id);
            let matching = payments.iter().find(|p| p.id == payment_hex);

            match matching {
                Some(p) if p.status == PaymentStatus::Succeeded => {
                    // Succeeded — commit InvoiceFulfill.
                    //
                    // Pre-flight the preimage: LDK has occasionally
                    // returned a preimage that doesn't hash to the
                    // payment_hash we were tracking the lock by
                    // (e.g. the `id` we matched on actually identifies
                    // a payment attempt rather than the BOLT11). If we
                    // commit a mismatch, the conformance check rejects
                    // it with "preimage does not match payment hash"
                    // and the operator gets no diagnostic context. Log
                    // the inputs ourselves so the next time it
                    // happens we have something to chase.
                    // Resolve the preimage. Two paths converge here:
                    //
                    //   - Lightning-routed pay: LDK's outbound record
                    //     (`list-payments`) carries the preimage on
                    //     status=succeeded.
                    //   - Cross-node self-pay (two operators sharing
                    //     one LDK node, A paying B's invoice): LDK
                    //     shortcircuits internally — the outbound
                    //     entry lands as status=succeeded but with
                    //     `preimage: None` because no Lightning hop
                    //     happened. The preimage lives on the
                    //     receive-side BOLT11 record, surfaced by
                    //     `get-payment-details`. Fall back to that
                    //     when list-payments doesn't have one.
                    let mut preimage = [0u8; 32];
                    let mut preimage_source = "list-payments";
                    let mut preimage_hex_opt = p.preimage_hex.clone();
                    if preimage_hex_opt.is_none() {
                        match cli.get_payment_preimage(&payment_hex) {
                            Ok(Some(p_inbound)) => {
                                preimage = p_inbound;
                                preimage_hex_opt = Some(hex::encode(p_inbound));
                                preimage_source = "get-payment-details (inbound fallback)";
                            }
                            Ok(None) => {
                                tracing::error!(
                                    "auto_complete_outbound: payment {}: LDK marked \
                                     outbound succeeded but neither list-payments nor \
                                     get-payment-details returned a preimage — skipping. \
                                     LDK record: id={} amount_msat={:?}",
                                    &payment_hex[..16],
                                    p.id,
                                    p.amount_msat
                                );
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    "auto_complete_outbound: payment {}: outbound has \
                                     no preimage and get-payment-details failed: {} — \
                                     skipping. LDK record: id={}",
                                    &payment_hex[..16],
                                    e,
                                    p.id
                                );
                                continue;
                            }
                        }
                    } else {
                        match hex::decode(preimage_hex_opt.as_ref().unwrap()) {
                            Ok(b) if b.len() == 32 => preimage.copy_from_slice(&b),
                            Ok(b) => {
                                tracing::error!(
                                    "auto_complete_outbound: payment {}: LDK preimage \
                                     wrong length ({} bytes, expected 32) — skipping; \
                                     LDK record: id={} preimage={:?}",
                                    &payment_hex[..16],
                                    b.len(),
                                    p.id,
                                    preimage_hex_opt
                                );
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    "auto_complete_outbound: payment {}: LDK preimage \
                                     not valid hex ({}) — skipping; LDK record: id={} \
                                     preimage={:?}",
                                    &payment_hex[..16],
                                    e,
                                    p.id,
                                    preimage_hex_opt
                                );
                                continue;
                            }
                        }
                    }
                    {
                        use bitcoin::hashes::{sha256, Hash};
                        let computed: [u8; 32] = *sha256::Hash::hash(&preimage).as_byte_array();
                        if computed != payment_id {
                            tracing::error!(
                                "auto_complete_outbound: payment {}: preimage from {} \
                                 doesn't hash to payment_hash — refusing to commit a \
                                 guaranteed-invalid Fulfill. \
                                 payment_hash={} preimage={} sha256(preimage)={} \
                                 LDK_record_id={}",
                                &payment_hex[..16],
                                preimage_source,
                                payment_hex,
                                preimage_hex_opt.as_deref().unwrap_or("(none)"),
                                hex::encode(computed),
                                p.id
                            );
                            continue;
                        }
                    }

                    let sequence = {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        match ledgers.get(&ledger_id) {
                            Some(arc) => arc.read().unwrap().next_sequence(),
                            None => continue,
                        }
                    };

                    // Witness was cached on `OpenInvoiceLock` at
                    // InvoiceLock-apply time so we can re-attach it
                    // here without round-tripping back to the wallet.
                    // Conformance: the cached witness still satisfies
                    // the descriptor over the lock's dep-17 preimage,
                    // which is exactly what InvoiceFulfill's check wants.
                    if lock.witness.stack.is_empty() {
                        tracing::error!(
                            "auto_complete_outbound: payment {}: lock has no cached \
                             witness (pre-fix InvoiceLock) — refusing to commit a \
                             guaranteed-invalid Fulfill. lock_sequence={} \
                             deposit_id={}",
                            &payment_hex[..16],
                            lock.lock_sequence,
                            hex::encode(lock.deposit_id)
                        );
                        continue;
                    }

                    let op = deposits_core::messages::LedgerOperation::InvoiceFulfill {
                        deposit_id: lock.deposit_id,
                        amount: lock.amount,
                        payment_id,
                        sequence_number: sequence,
                        witness: lock.witness.clone(),
                        preimage,
                    };

                    match self.commit_operation(&ledger_id, op).await {
                        Ok(_) => tracing::info!(
                            "auto_complete_outbound: fulfilled payment {}..., {} msat",
                            &payment_hex[..16],
                            lock.amount
                        ),
                        Err(e) => tracing::error!(
                            "auto_complete_outbound: payment {}: commit failed: {} \
                             (lock_sequence={} deposit_id={} preimage_hex={:?})",
                            &payment_hex[..16],
                            e,
                            lock.lock_sequence,
                            hex::encode(lock.deposit_id),
                            preimage_hex_opt
                        ),
                    }
                }
                Some(p) if p.status == PaymentStatus::Failed => {
                    // Failed — commit InvoiceFail
                    let sequence = {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        match ledgers.get(&ledger_id) {
                            Some(arc) => arc.read().unwrap().next_sequence(),
                            None => continue,
                        }
                    };

                    let op = deposits_core::messages::LedgerOperation::InvoiceFail {
                        deposit_id: lock.deposit_id,
                        amount: lock.amount,
                        payment_id,
                        sequence_number: sequence,
                    };

                    match self.commit_operation(&ledger_id, op).await {
                        Ok(_) => tracing::info!(
                            "auto_complete_outbound: failed payment {}..., {} msat unlocked",
                            &payment_hex[..16],
                            lock.amount
                        ),
                        Err(e) => tracing::error!(
                            "auto_complete_outbound: failed to record fail {}...: {}",
                            &payment_hex[..16],
                            e
                        ),
                    }
                }
                _ => {
                    // Still pending or not found in LDK — leave alone
                    tracing::debug!(
                        "auto_complete_outbound: payment {}... still pending",
                        &payment_hex[..16]
                    );
                }
            }
        }
    }

    /// Auto-rotate the quorum when it's within
    /// `rotate_before_expiry_days × 144` blocks of `quorum_expiry`.
    ///
    /// Per-ledger state machine (matches the manual `quorum refresh`
    /// CLI semantics, just driven from the periodic loop):
    ///
    ///   1. Skip ledgers we don't operate or that have no active quorum.
    ///   2. Skip if `current_block + threshold < quorum_expiry` —
    ///      plenty of time, no work this cycle.
    ///   3. For each active member m not represented in
    ///      `next_quorum_members` with a fresh `membership_until`,
    ///      synthesize a `quorum_add` request and run it through the
    ///      handler. The handler waits for the member's `QuorumJoin`
    ///      reply with its own timeout — offline members fail fast and
    ///      we move on, picking them up next cycle.
    ///   4. Once every active member is fresh in `next_quorum_members`,
    ///      synthesize a `quorum_begin` request to rotate the on-chain
    ///      UTXO with the extended membership.
    ///
    /// Idempotent and incremental: each tick advances whatever it can.
    /// Safe to invoke at the same cadence as the other periodic tasks
    /// (5s fast / 60s normal); the per-member RPC has its own
    /// rate-limiting so this doesn't spam offline members.
    pub async fn auto_quorum_refresh(self: &Arc<Self>) {
        // Test/recovery hook: paired with `.pause_auto_dispute_actions`
        // — when a Tier-3 test wants to drive the cosigner-driven
        // dispute path, the accused operator must NOT silently
        // self-rescue first. Drop a `.pause_auto_quorum_refresh`
        // marker in the operator's data dir to disable refreshes
        // without having to bring the daemon down.
        if self.data_dir.join(".pause_auto_quorum_refresh").exists() {
            tracing::debug!(
                ".pause_auto_quorum_refresh marker present — skipping refresh cycle"
            );
            return;
        }
        let threshold_blocks: u32 = self
            .rotate_before_expiry_days
            .saturating_mul(144);
        if threshold_blocks == 0 {
            return;
        }
        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(_) => return,
        };

        // Snapshot owned ledgers + their quorum state. Drop the lock
        // before issuing any daemon RPC so a slow handler doesn't
        // hold up other periodic tasks.
        let ledgers_to_check: Vec<LedgerRefreshSnapshot> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter_map(|(id, arc)| {
                    // Skip fork branches (compound key with extra suffix)
                    // and ledgers we don't operate.
                    if id.len() != 64 {
                        return None;
                    }
                    let l = arc.read().unwrap();
                    if l.operator_key() != self.node_id {
                        return None;
                    }
                    let expiry = l.state.quorum_expiry?;
                    if l.state.quorum_state
                        != deposits_core::types::QuorumState::Active
                    {
                        return None;
                    }
                    Some(LedgerRefreshSnapshot {
                        ledger_id: id.clone(),
                        quorum_expiry: expiry,
                        active_members: l.state.quorum_members.clone(),
                        pending_members: l.state.next_quorum_members.clone(),
                        ruleset_name: l.state.active_ruleset_name.clone(),
                    })
                })
                .collect()
        };

        for snap in ledgers_to_check {
            // Trigger condition: chain tip plus threshold reaches expiry.
            if current_block.saturating_add(threshold_blocks) < snap.quorum_expiry {
                continue;
            }
            // Idempotency: don't double-launch per-ledger work. Same set
            // used by the rotation-in-flight guard further down.
            {
                let mut in_flight = self.rotating_ledgers.lock().unwrap();
                if in_flight.contains(&snap.ledger_id) {
                    tracing::debug!(
                        "auto_quorum_refresh: ledger {}... per-cycle work already in flight; skipping",
                        &snap.ledger_id[..16]
                    );
                    continue;
                }
                in_flight.insert(snap.ledger_id.clone());
            }
            // Detach the per-ledger work as a background task. The
            // refresh loop's per-member consent calls can each take 10s
            // (the consent timeout); with the periodic-task budget also
            // at 10s, doing this inline busts the budget the first time
            // a member doesn't respond. Spawning per-ledger lets the
            // budget bound only the snapshot phase, while the actual
            // refresh / candidate-queue / rotation runs as long as it
            // needs.
            let node = Arc::clone(self);
            let snap = snap;
            tokio::spawn(async move {
                node.run_quorum_refresh_for(snap, current_block, threshold_blocks)
                    .await;
            });
        }
    }

    /// The per-ledger refresh + candidate-queue + rotation work, lifted
    /// out of the periodic loop and run as a detached task. See
    /// `auto_quorum_refresh` for the dispatch site.
    pub(crate) async fn run_quorum_refresh_for(
        self: Arc<Self>,
        snap: LedgerRefreshSnapshot,
        _periodic_current_block: u32,
        threshold_blocks: u32,
    ) {
        // Always remove from the in-flight set on exit, regardless of
        // success / failure / panic. Constructing a guard lets us do
        // that without sprinkling cleanup at every early return.
        let _guard = InFlightGuard {
            set: Arc::clone(&self.rotating_ledgers),
            id: snap.ledger_id.clone(),
        };
        // Re-read chain tip INSIDE the spawned task. The periodic-loop
        // snapshot is taken once per ~10s tick, but spawned tasks here
        // can run for minutes (consent timeouts × non-fresh members ×
        // candidate-queue attempts). By the time the work runs, the
        // chain has typically advanced past whatever the periodic
        // captured — and the `post_expiry` gate would otherwise read
        // stale, skipping the candidate-queue path. Read fresh.
        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(_) => return,
        };
        {
            // Past expiry: behaviour depends on the ledger's ruleset.
            //
            // Legacy: cosigners refuse every op past quorum_expiry
            // (`post_expiry_cosign_refused`), so a refresh attempt
            // 0/N-times-out every periodic cycle. Bail quietly.
            //
            // cltv-offset-v2 / cltv-offset-literal: DEP-05 §Lifecycle
            // cascade applies. The cosign coordinator picks the right
            // tier threshold (majority at Tier-0 post-expiry, degraded
            // at higher tiers), the wallet picks the right on-chain
            // spend tier, and the cosigner-side gate honours
            // establishment ops past expiry. Drive the self-rescue
            // autonomously without waiting for `quorum repair`. Opt
            // out with `DEPOSITS_DISABLE_AUTO_SELF_RESCUE=1`.
            let cascade_active = matches!(
                snap.ruleset_name.as_str(),
                "cltv-offset-v2" | "cltv-offset-literal"
            );
            let post_expiry = current_block > snap.quorum_expiry;
            let auto_self_rescue_disabled = std::env::var(
                "DEPOSITS_DISABLE_AUTO_SELF_RESCUE",
            )
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
            if post_expiry && (!cascade_active || auto_self_rescue_disabled) {
                tracing::debug!(
                    "auto_quorum_refresh: ledger {}... past quorum_expiry={} \
                     (current {}), skipping (cascade_active={}, disabled={}) — \
                     use `quorum repair` to invoke the cascade explicitly",
                    &snap.ledger_id[..16],
                    snap.quorum_expiry,
                    current_block,
                    cascade_active,
                    auto_self_rescue_disabled,
                );
                return;
            }
            tracing::info!(
                "auto_quorum_refresh: ledger {}... quorum_expiry={} \
                 within {}-block threshold of current {}, refreshing",
                &snap.ledger_id[..16],
                snap.quorum_expiry,
                threshold_blocks,
                current_block
            );

            // New membership_until: pick a value comfortably past the
            // next refresh window. Default extension = 4 × threshold so
            // the next auto-refresh will trigger at ~25% of the
            // membership lifetime remaining.
            let extension_blocks = threshold_blocks.saturating_mul(4).max(1000);
            let new_membership_until = current_block.saturating_add(extension_blocks);
            let staleness_floor = current_block.saturating_add(threshold_blocks);

            let mut all_fresh = true;
            for m in &snap.active_members {
                let pending_match = snap
                    .pending_members
                    .iter()
                    .find(|p| p.pubkey == m.pubkey);
                let fresh = pending_match
                    .and_then(|p| p.membership_until)
                    .map(|until| until >= staleness_floor)
                    .unwrap_or(false);
                if fresh {
                    continue;
                }
                all_fresh = false;

                let prefix = &m.pubkey.to_string()[..16];
                tracing::info!(
                    "auto_quorum_refresh: requesting refresh from member {}...",
                    prefix
                );

                let mut params = serde_json::json!({
                    "member_pubkey": m.pubkey.to_string(),
                    "member_ledger_id": m.ledger_id.clone(),
                    "membership_until": new_membership_until,
                });
                if let Some(v) = m.min_fee_bps {
                    params["min_fee_bps"] = (v as u64).into();
                }
                if let Some(v) = m.min_fee_fixed {
                    params["min_fee_fixed"] = serde_json::Value::from(v);
                }
                if let Some(v) = m.max_fee_period {
                    params["max_fee_period"] = serde_json::Value::from(v);
                }

                let req = crate::nostr::LedgerRequest {
                    action: "quorum_add".into(),
                    ledger_id: snap.ledger_id.clone(),
                    params,
                    event_id: String::new(),
                    sender: String::new(),
                    timestamp: 0,
                    gift_wrap_sender: None,
                    subkey_account: None,
                    subkey_attestation: None,
                    addressee: None,
                };
                let (success, _, error) = self.process_quorum_add_request(&req).await;
                if success {
                    tracing::info!(
                        "auto_quorum_refresh: member {}... refreshed",
                        prefix
                    );
                    continue;
                }
                tracing::warn!(
                    "auto_quorum_refresh: member {}... not yet refreshed: {}",
                    prefix,
                    error.unwrap_or_default()
                );

                // Post-expiry self-rescue with a candidate queue: when
                // an existing member won't refresh, pop the next pre-
                // curated candidate and try to enlist them. The same
                // process_quorum_add_request flow runs the consent
                // dance with the candidate. On success they're staged
                // and the dead member gets removed; on failure the
                // candidate is dropped (they had their shot) and the
                // next periodic cycle tries the next one. Up to
                // `MAX_CANDIDATE_ATTEMPTS_PER_CYCLE` tried per
                // unresponsive member to bound the per-cycle cost.
                if !(post_expiry && cascade_active) {
                    continue;
                }
                const MAX_CANDIDATE_ATTEMPTS_PER_CYCLE: usize = 3;
                let mut queue = crate::candidate_queue::CandidateQueue::load(&self.data_dir);
                let mut attempts = 0usize;
                while attempts < MAX_CANDIDATE_ATTEMPTS_PER_CYCLE {
                    let Some(candidate) = queue.pop_front(&self.data_dir) else {
                        tracing::info!(
                            "auto_quorum_refresh: candidate queue empty — no \
                             replacement for unresponsive member {}",
                            prefix
                        );
                        break;
                    };
                    attempts += 1;
                    // WARN — notable enough that operators with
                    // RUST_LOG=warn should see the swap attempt.
                    tracing::warn!(
                        "auto_quorum_refresh: trying candidate {}... as replacement \
                         for {} (attempt {}/{})",
                        &candidate.pubkey[..16.min(candidate.pubkey.len())],
                        prefix,
                        attempts,
                        MAX_CANDIDATE_ATTEMPTS_PER_CYCLE
                    );
                    let candidate_req = crate::nostr::LedgerRequest {
                        action: "quorum_add".into(),
                        ledger_id: snap.ledger_id.clone(),
                        params: serde_json::json!({
                            "member_pubkey": candidate.pubkey,
                            "member_ledger_id": candidate.member_ledger_id,
                            "membership_until": new_membership_until,
                        }),
                        event_id: String::new(),
                        sender: String::new(),
                        timestamp: 0,
                        gift_wrap_sender: None,
                        subkey_account: None,
                        subkey_attestation: None,
                        addressee: None,
                    };
                    let (cs, _, cerr) =
                        self.process_quorum_add_request(&candidate_req).await;
                    if cs {
                        tracing::info!(
                            "auto_quorum_refresh: candidate consented; removing \
                             unresponsive member {} and staging replacement",
                            prefix
                        );
                        // Remove the dead member from the active set so the
                        // upcoming QuorumBegin's voter_set is just the
                        // refreshed staged list.
                        let remove_req = crate::nostr::LedgerRequest {
                            action: "quorum_remove".into(),
                            ledger_id: snap.ledger_id.clone(),
                            params: serde_json::json!({
                                "quorum_member": m.pubkey.to_string(),
                            }),
                            event_id: String::new(),
                            sender: String::new(),
                            timestamp: 0,
                            gift_wrap_sender: None,
                            subkey_account: None,
                            subkey_attestation: None,
                            addressee: None,
                        };
                        let (rs, _, rerr) =
                            self.process_quorum_remove_request(&remove_req).await;
                        if !rs {
                            tracing::warn!(
                                "auto_quorum_refresh: failed to remove {} \
                                 after staging candidate: {}",
                                prefix,
                                rerr.unwrap_or_default()
                            );
                        }
                        break;
                    } else {
                        tracing::warn!(
                            "auto_quorum_refresh: candidate {}... didn't consent: {} \
                             — dropping from queue, trying next",
                            &candidate.pubkey[..16.min(candidate.pubkey.len())],
                            cerr.unwrap_or_default()
                        );
                    }
                }
            }

            // After the per-member loop, re-read pending_members and
            // re-check freshness. Only rotate if every active member
            // is now fresh (the `all_fresh` flag was a best-guess
            // before the RPCs ran; refresh the snapshot to be certain).
            let still_all_fresh = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let arc = match ledgers.get(&snap.ledger_id) {
                    Some(a) => a,
                    None => return,
                };
                let l = arc.read().unwrap();
                l.state.quorum_members.iter().all(|m| {
                    l.state
                        .next_quorum_members
                        .iter()
                        .find(|p| p.pubkey == m.pubkey)
                        .and_then(|p| p.membership_until)
                        .map(|until| until >= staleness_floor)
                        .unwrap_or(false)
                })
            };
            let _ = all_fresh;

            if !still_all_fresh {
                if post_expiry && cascade_active {
                    // Post-expiry self-rescue: skip the all-fresh gate.
                    // Some members may be unreachable (the very reason
                    // we're rescuing). The cosign coordinator picks
                    // the tier threshold based on chain tip and
                    // collects whatever sigs are available; whoever
                    // doesn't respond is dropped from the new quorum.
                    tracing::info!(
                        "auto_quorum_refresh: ledger {}... post-expiry self-\
                         rescue — proceeding without all-fresh gate (some \
                         members may be unreachable)",
                        &snap.ledger_id[..16]
                    );
                } else {
                    tracing::info!(
                        "auto_quorum_refresh: ledger {}... not all members fresh; \
                         will retry next cycle",
                        &snap.ledger_id[..16]
                    );
                    return;
                }
            }

            // Already inside a per-ledger spawned task (guarded by the
            // in_flight set entered at dispatch time). Just call the
            // rotation handler directly — InFlightGuard releases the
            // slot when this function returns.
            tracing::info!(
                "auto_quorum_refresh: ledger {}... rotating",
                &snap.ledger_id[..16]
            );

            let begin_req = crate::nostr::LedgerRequest {
                action: "quorum_begin".into(),
                ledger_id: snap.ledger_id.clone(),
                params: serde_json::json!({}),
                event_id: String::new(),
                sender: String::new(),
                timestamp: 0,
                gift_wrap_sender: None,
                subkey_account: None,
                subkey_attestation: None,
                addressee: None,
            };
            let (success, _, error) =
                self.process_quorum_begin_request(&begin_req).await;
            if success {
                tracing::info!(
                    "auto_quorum_refresh: ledger {}... rotated",
                    &snap.ledger_id[..16]
                );
            } else {
                tracing::warn!(
                    "auto_quorum_refresh: ledger {}... rotate failed: {}",
                    &snap.ledger_id[..16],
                    error.unwrap_or_default()
                );
            }
        }
    }

    /// Operator-side liquidity-drip ticker.
    ///
    /// Loads `<data_dir>/operator_drips.json`, iterates each active
    /// plan, and advances each one's state machine by at most one
    /// step per cycle:
    ///
    ///   1. If the plan has no `buffer_index` yet → open a buffer
    ///      deposit via `internal_buffer_open` (auto-allocated from
    ///      the shared `buffer_indices.json` registry) and persist
    ///      the index back to the plan.
    ///   2. Else if the buffer has zero balance and this plan has
    ///      never ticked → fill it via `internal_buffer_fill` for
    ///      `target_deposit_sats * 1000` msats.
    ///   3. Else if the interval has elapsed → drain `decrement_sats`
    ///      via `internal_buffer_drain`. Frees that much operator
    ///      reserve capacity back to the pool.
    ///
    /// One step per plan per cycle keeps the periodic budget bounded.
    /// Disable via `.pause_auto_drip_self_liquidity` marker.
    pub async fn auto_drip_self_liquidity(self: &Arc<Self>) {
        if self.data_dir.join(".pause_auto_drip_self_liquidity").exists() {
            tracing::debug!(
                ".pause_auto_drip_self_liquidity marker present — skipping cycle"
            );
            return;
        }
        let mut registry = match crate::operator_drips::DripRegistry::load(&self.data_dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("auto_drip_self_liquidity: load registry failed: {}", e);
                return;
            }
        };
        if registry.plans.is_empty() {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut dirty = false;
        for plan in registry.plans.iter_mut() {
            if plan.paused {
                continue;
            }

            // ── Step 1: open + fund the buffer atomically if we haven't yet ──
            // One Batch([DepositOpen, InvoiceCredit]) — see
            // internal_buffer_open_and_fund. The previous split (open one
            // cycle, fund the next, as two separate cosign rounds) raced quorum
            // replication and stranded the drip at DepositNotFound.
            if plan.buffer_index.is_none() {
                let target_msats = plan.target_deposit_sats.saturating_mul(1_000);
                match self
                    .internal_buffer_open_and_fund(Some(plan.ledger_id.clone()), target_msats)
                    .await
                {
                    Ok(out) => {
                        plan.buffer_index = Some(out.index);
                        dirty = true;
                        tracing::info!(
                            "auto_drip_self_liquidity: opened+funded buffer #{} ({} sats) \
                             for plan '{}' on ledger {}…",
                            out.index,
                            plan.target_deposit_sats,
                            plan.alias,
                            &plan.ledger_id[..16.min(plan.ledger_id.len())],
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "auto_drip_self_liquidity: open+fund failed for plan '{}': {}",
                            plan.alias,
                            e,
                        );
                    }
                }
                continue;
            }

            let buffer_index = plan.buffer_index.unwrap();

            // ── Step 2: drip drain on interval ──
            if !plan.is_due(now) {
                continue;
            }
            let current_balance_msats = self
                .internal_buffer_balance_msats(buffer_index)
                .unwrap_or(0);
            let decrement_msats = plan.decrement_sats.saturating_mul(1_000);
            if current_balance_msats < decrement_msats {
                tracing::info!(
                    "auto_drip_self_liquidity: plan '{}' underfunded ({} < {} msats); \
                     stopping ticks",
                    plan.alias,
                    current_balance_msats,
                    decrement_msats,
                );
                continue;
            }
            match self.internal_buffer_drain(buffer_index, decrement_msats).await {
                Ok(new_balance) => {
                    use bitcoin::secp256k1::rand::rngs::OsRng;
                    use bitcoin::secp256k1::rand::RngCore;
                    plan.last_tick_unix = now;
                    plan.ticks_completed += 1;
                    plan.next_tick_unix = plan.next_tick_at(now, OsRng.next_u64());
                    dirty = true;
                    tracing::info!(
                        "auto_drip_self_liquidity: drained {} sats from plan '{}' \
                         (tick {}, balance now {} msats, next in {}s)",
                        plan.decrement_sats,
                        plan.alias,
                        plan.ticks_completed,
                        new_balance,
                        plan.next_tick_unix.saturating_sub(now),
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "auto_drip_self_liquidity: drain failed for plan '{}': {}",
                        plan.alias,
                        e,
                    );
                }
            }
        }

        if dirty {
            if let Err(e) = registry.save(&self.data_dir) {
                tracing::warn!("auto_drip_self_liquidity: persist registry failed: {}", e);
            }
        }
    }
}

/// Snapshot of one ledger's quorum state, captured by the periodic
/// task before dispatching the per-ledger work into a spawned task.
pub(crate) struct LedgerRefreshSnapshot {
    pub ledger_id: String,
    pub quorum_expiry: u32,
    pub active_members: Vec<deposits_core::types::QuorumMember>,
    pub pending_members: Vec<deposits_core::types::QuorumMember>,
    pub ruleset_name: String,
}

/// RAII helper: removes the ledger_id from the in-flight set on drop,
/// regardless of how the per-ledger task exits.
struct InFlightGuard {
    set: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.id);
    }
}
