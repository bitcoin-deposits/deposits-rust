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
    /// This polls LDK for payment status and creates InvoiceCredit operations
    /// for any pending invoices that have been successfully paid.
    pub async fn auto_credit_received_payments(&self) {
        use crate::ldk_cli::LdkCli;

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

        // Query LDK for payment status
        let cli = LdkCli::from_env();
        let payments = match cli.list_payments() {
            Ok(resp) => {
                tracing::info!("auto_credit: LDK returned {} payments", resp.payments.len());
                resp.payments
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
                // status: 0 = pending, 1 = succeeded, 2 = failed
                match payment.status {
                    1 => {
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
                    2 => {
                        // Payment failed - remove from pending (invoice expired or rejected)
                        tracing::warn!(
                            "Invoice {}... payment failed, removing from pending",
                            &payment_hash_hex[..16]
                        );
                        self.pending_invoices.lock().unwrap().remove(&payment_hash);
                    }
                    _ => {
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

    /// Resolve open outbound invoice locks by checking LDK payment status.
    ///
    /// Scans all owned ledgers for open_invoice_locks. For each, queries LDK
    /// for the payment status and commits InvoiceFulfill (if succeeded) or
    /// InvoiceFail (if failed). Pending payments are left alone.
    pub async fn auto_complete_outbound_payments(&self) {
        use crate::ldk_cli::LdkCli;

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

        let cli = LdkCli::from_env();
        let payments = match cli.list_payments() {
            Ok(resp) => resp.payments,
            Err(e) => {
                tracing::warn!("auto_complete_outbound: failed to list payments: {}", e);
                return;
            }
        };

        for (ledger_id, payment_id, lock) in open_locks {
            let payment_hex = hex::encode(payment_id);
            let matching = payments.iter().find(|p| p.id == payment_hex);

            match matching {
                Some(p) if p.status == 1 => {
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
                    let mut preimage_hex_opt = p.preimage.clone();
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
                    // Conformance: `verify_witness(descriptor, witness,
                    // invoice_lock_signing_message(deposit_id,
                    // payment_id, amount))` — same message Lock signed.
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
                Some(p) if p.status == 2 => {
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
}
