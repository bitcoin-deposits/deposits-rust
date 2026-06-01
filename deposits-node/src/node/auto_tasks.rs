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
        struct LedgerSnapshot {
            ledger_id: String,
            quorum_expiry: u32,
            active_members: Vec<deposits_core::types::QuorumMember>,
            pending_members: Vec<deposits_core::types::QuorumMember>,
        }
        let ledgers_to_check: Vec<LedgerSnapshot> = {
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
                    Some(LedgerSnapshot {
                        ledger_id: id.clone(),
                        quorum_expiry: expiry,
                        active_members: l.state.quorum_members.clone(),
                        pending_members: l.state.next_quorum_members.clone(),
                    })
                })
                .collect()
        };

        for snap in ledgers_to_check {
            // Trigger condition: chain tip plus threshold reaches expiry.
            if current_block.saturating_add(threshold_blocks) < snap.quorum_expiry {
                continue;
            }
            // Past expiry: behaviour depends on the ledger's ruleset.
            //
            // Legacy: cosigners refuse every op past quorum_expiry
            // (`post_expiry_cosign_refused`), so a refresh attempt
            // 0/N-times-out every periodic cycle. Bail quietly.
            //
            // cltv-offset-v2 / cltv-offset-literal: DEP-05 §Lifecycle
            // cascade applies. The cosign coordinator picks the right
            // threshold for the current tier (majority at Tier-0
            // post-expiry, degraded at higher tiers), and the wallet
            // picks the right on-chain spend tier. Auto-refresh can
            // now drive the operator's self-rescue path without manual
            // `quorum repair`. The cosigner-side rotation_sign handler
            // honours the lifecycle gate too.
            //
            // TODO: the proactive auto_quorum_refresh path is still
            // tuned for the pre-expiry "rotate-before-deadline" idiom
            // (members re-add → QuorumBegin). The post-expiry path
            // needs different orchestration (e.g. fewer member-consent
            // requests since cosigners may be offline). For now the
            // explicit `quorum repair` CLI is the supported entry
            // point past expiry; the auto-refresh leaves the cascade
            // dormant unless invoked manually.
            if current_block > snap.quorum_expiry {
                tracing::debug!(
                    "auto_quorum_refresh: ledger {}... past quorum_expiry={} \
                     (current {}), skipping — use `quorum repair` to invoke \
                     the lifecycle cascade explicitly",
                    &snap.ledger_id[..16],
                    snap.quorum_expiry,
                    current_block
                );
                continue;
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
                };
                let (success, _, error) = self.process_quorum_add_request(&req).await;
                if success {
                    tracing::info!(
                        "auto_quorum_refresh: member {}... refreshed",
                        prefix
                    );
                } else {
                    tracing::warn!(
                        "auto_quorum_refresh: member {}... not yet refreshed: {}",
                        prefix,
                        error.unwrap_or_default()
                    );
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
                    None => continue,
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
                tracing::info!(
                    "auto_quorum_refresh: ledger {}... not all members fresh; \
                     will retry next cycle",
                    &snap.ledger_id[..16]
                );
                continue;
            }

            // Detach the actual rotation as a background task. It can
            // take minutes (cosign collection + on-chain confs +
            // QuorumBegin op cosign), far longer than the 10s periodic
            // task budget. The rotating_ledgers set prevents the next
            // periodic cycle from double-launching while the prior
            // rotation is still in flight.
            {
                let mut in_flight = self.rotating_ledgers.lock().unwrap();
                if in_flight.contains(&snap.ledger_id) {
                    tracing::debug!(
                        "auto_quorum_refresh: ledger {}... rotation already in flight; skipping",
                        &snap.ledger_id[..16]
                    );
                    continue;
                }
                in_flight.insert(snap.ledger_id.clone());
            }

            tracing::info!(
                "auto_quorum_refresh: ledger {}... all members fresh, rotating (detached)",
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
            };
            let node = Arc::clone(self);
            let in_flight_set = Arc::clone(&self.rotating_ledgers);
            let ledger_id_for_task = snap.ledger_id.clone();
            tokio::spawn(async move {
                let (success, _, error) =
                    node.process_quorum_begin_request(&begin_req).await;
                if success {
                    tracing::info!(
                        "auto_quorum_refresh: ledger {}... rotated",
                        &ledger_id_for_task[..16]
                    );
                } else {
                    tracing::warn!(
                        "auto_quorum_refresh: ledger {}... rotate failed: {}",
                        &ledger_id_for_task[..16],
                        error.unwrap_or_default()
                    );
                }
                in_flight_set.lock().unwrap().remove(&ledger_id_for_task);
            });
        }
    }
}
