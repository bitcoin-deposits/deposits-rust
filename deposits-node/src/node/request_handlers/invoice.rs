//! Invoice request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    /// Process a make_invoice request - create Lightning invoice for deposit credit
    ///
    /// Uses LdkBackend to talk to the ldk-server sidecar (same as `deposits-node lightning invoice`)
    ///
    /// Params:
    /// - descriptor: full miniscript expression that pays out the deposit, OR
    /// - deposit_id: 32-char hex (16-byte) deposit identifier (looked up in
    ///               the operator's existing deposit state — for clients that
    ///               only know the ID, e.g. LNURL gateways routing to a known
    ///               deposit)
    /// - amount_sats: amount for the invoice
    /// - description: optional invoice description
    /// - receive_witness: required if the deposit has receive_requires_sig set
    pub(crate) async fn process_make_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Caller may pass either `descriptor` (preferred — full identity)
        // or `deposit_id` (in which case we look up the descriptor from
        // existing ledger state). At least one must be present.
        let (descriptor, deposit_id) = match super::deposits::parse_descriptor_param(request) {
            Ok(parts) => parts,
            Err(_descriptor_err) => match super::deposits::parse_deposit_id_param(request) {
                Ok(id) => {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let descriptor = ledgers
                        .get(&request.ledger_id)
                        .and_then(|arc| {
                            arc.read()
                                .unwrap()
                                .state
                                .deposits
                                .get(&id)
                                .map(|d| d.descriptor.clone())
                        });
                    match descriptor {
                        Some(d) => (d, id),
                        None => {
                            return (
                                false,
                                None,
                                Some("Unknown deposit_id and no descriptor provided".to_string()),
                            )
                        }
                    }
                }
                Err(_) => {
                    return (
                        false,
                        None,
                        Some("Missing descriptor or deposit_id parameter".to_string()),
                    )
                }
            },
        };

        // If the deposit exists with receive_requires_sig, require the
        // caller to attach a `receive_witness` that satisfies the descriptor.
        {
            let needs_witness = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&request.ledger_id)
                    .and_then(|ledger_arc| {
                        let ledger = ledger_arc.read().unwrap();
                        ledger
                            .state
                            .deposits
                            .get(&deposit_id)
                            .map(|d| d.receive_requires_sig)
                    })
                    .unwrap_or(false)
            };
            if needs_witness {
                let tip = self.wallet.get_block_height().unwrap_or(0);
                if let Err(msg) =
                    super::deposits::verify_receive_witness(&descriptor, &deposit_id, request, tip)
                {
                    return (false, None, Some(msg));
                }
            }
        }

        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => {
                return (
                    false,
                    None,
                    Some("Missing amount_sats parameter".to_string()),
                )
            }
        };

        let description = request
            .params
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("Deposit credit");

        // NIP-57 zaps: when the LNURL gateway provides description_hash
        // (sha256 of the urlencoded zap-request JSON), the invoice must
        // commit to it via the BOLT11 `h` field instead of `d`.
        // Otherwise the wallet's zap detection — which compares the
        // invoice's description_hash against sha256(its zap request) —
        // won't recognize the invoice as honoring the zap.
        let description_hash = request
            .params
            .get("description_hash")
            .and_then(|v| v.as_str())
            .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()));

        let amount_msat = amount_sats * 1000;

        // Check collateral obligation limits before creating the invoice
        if let Some(err) = self.check_collateral_obligation_limit(&request.ledger_id, amount_msat) {
            return (false, None, Some(err));
        }

        // Check per-deposit balance limit
        if let Some(err) =
            self.check_deposit_balance_limit(&request.ledger_id, &deposit_id, amount_msat)
        {
            return (false, None, Some(err));
        }

        // Create invoice via the configured Lightning backend (same as
        // `deposits-node lightning invoice`). The backend shells out to a
        // sidecar (ldk-server-cli / lnd / cln) with a BLOCKING call and no
        // timeout, so run it on a blocking thread under a hard cap: a missing or
        // unreachable backend must fail fast with a clear error rather than hang
        // until the caller (e.g. the LNURL gateway) times out. spawn_blocking
        // also isolates the lnd/cln `from_env` panic-on-misconfig into a JoinError
        // instead of taking down the worker.
        //
        // Must be shorter than callers' own waits or they time out first and
        // never see our clear error — the LNURL gateway waits 15s
        // (deposits-lnurl lnurlp_callback), so cap well under that.
        const BACKEND_INVOICE_TIMEOUT_SECS: u64 = 10;
        let desc_owned = description.to_string();
        let dh_owned: Option<String> = description_hash.map(|s| s.to_string());
        let invoice_result = match tokio::time::timeout(
            std::time::Duration::from_secs(BACKEND_INVOICE_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                let cli = crate::lightning_backend::from_env();
                match dh_owned {
                    Some(dh) => cli.create_invoice_with_desc_hash(amount_msat, &dh),
                    None => cli.create_invoice(amount_msat, &desc_owned),
                }
            }),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(join)) => {
                return (
                    false,
                    None,
                    Some(format!("Lightning backend unavailable: {}", join)),
                );
            }
            Err(_) => {
                return (
                    false,
                    None,
                    Some(format!(
                        "Lightning backend did not return an invoice within {}s — check the \
                         daemon's LDK_*/LIGHTNING_BACKEND config and that the sidecar is reachable",
                        BACKEND_INVOICE_TIMEOUT_SECS
                    )),
                );
            }
        };
        match invoice_result {
            Ok(invoice_str) => {
                // Parse the invoice to get the payment hash
                let payment_hash = match Bolt11Invoice::from_str(&invoice_str) {
                    Ok(inv) => {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(inv.payment_hash().as_ref());
                        hash
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse created invoice: {}", e);
                        // Generate a hash from the invoice string as fallback
                        use bitcoin::hashes::{sha256, Hash};
                        let hash = sha256::Hash::hash(invoice_str.as_bytes());
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash.as_ref());
                        arr
                    }
                };

                // Track the pending invoice for crediting when paid
                let pending = PendingInvoice {
                    ledger_id: request.ledger_id.clone(),
                    deposit_id,
                    descriptor: descriptor.clone(),
                    amount_msat,
                    invoice: invoice_str.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    payment_hash_hex: hex::encode(payment_hash),
                };

                self.pending_invoices
                    .lock()
                    .unwrap()
                    .insert(payment_hash, pending);
                self.save_pending_invoices();

                tracing::info!(
                    "Created invoice for {} amount={} sats, hash={}",
                    hex::encode(deposit_id),
                    amount_sats,
                    hex::encode(&payment_hash[..8])
                );

                // Operator-side attestation. Reuses the cosign canonical
                // message (`invoice_cosign_signing_message`) so the
                // existing fraud-proof verifier can validate either
                // signature; the operator's "ledger_hash" portion is
                // their own ledger's tip content_hash.
                //
                // Without this, only the cosigner had skin in the game
                // for an uncredited-payment fraud proof — adding the
                // operator's signature lets a depositor present
                // dual-attestation evidence and burn the operator's
                // collateral too.
                let (operator_ledger_hash_hex, operator_signature_hex) = {
                    use bitcoin::secp256k1::{Keypair, Message};
                    let operator_ledger_hash = {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        ledgers
                            .get(&request.ledger_id)
                            .and_then(|arc| {
                                arc.read()
                                    .unwrap()
                                    .history
                                    .last()
                                    .map(|u| u.content_hash)
                            })
                            .unwrap_or([0u8; 32])
                    };
                    let msg_hash = deposits_core::signature_utils::invoice_cosign_signing_message(
                        &request.ledger_id,
                        &payment_hash,
                        &deposit_id,
                        amount_msat,
                        &operator_ledger_hash,
                    );
                    use deposits_signer_api::{SigPurpose, SignContext};
                    let sig = match self.handler.signer.bip340_sign(
                        &SignContext::no_ledger(SigPurpose::InvoiceCosign),
                        &msg_hash,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            return (
                                false,
                                None,
                                Some(format!("invoice cosign sign: {}", e)),
                            )
                        }
                    };
                    (hex::encode(operator_ledger_hash), hex::encode(sig))
                };
                let operator_pubkey_hex = self.node_id_hex.clone();

                // Request co-signature from quorum member (if post-rotation)
                let requires_cosign = self.is_quorum_active(&request.ledger_id);
                if requires_cosign {
                    let params = serde_json::json!({
                        "payment_hash": hex::encode(payment_hash),
                        "deposit_id": hex::encode(deposit_id),
                        "amount_msat": amount_msat,
                        "invoice": &invoice_str,
                    });

                    let mut notification_rx = self.nostr.create_notification_receiver();
                    let req_id = match self
                        .nostr
                        .send_ledger_request(&request.ledger_id, "cosign_invoice", params)
                        .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            return (
                                false,
                                None,
                                Some(format!("Failed to send cosign_invoice: {:?}", e)),
                            );
                        }
                    };
                    self.track_sent_event(&req_id);

                    // Poll for response (3s timeout)
                    let deadline =
                        tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
                    let mut cosign_result: Option<serde_json::Value> = None;
                    loop {
                        // Drain notifications to trigger response processing
                        match tokio::time::timeout(
                            tokio::time::Duration::from_millis(100),
                            notification_rx.recv(),
                        )
                        .await
                        {
                            Ok(Ok(n)) => {
                                self.nostr.dispatch_or_extract_request(n, "");
                            }
                            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                            _ => {}
                        }
                        // Check for our response
                        while let Some(response) = self.nostr.try_recv_response() {
                            if response.request_id == req_id && response.success {
                                cosign_result = response.result.clone();
                                break;
                            }
                        }
                        if cosign_result.is_some() || tokio::time::Instant::now() >= deadline {
                            break;
                        }
                    }

                    match cosign_result {
                        Some(r) => {
                            let result = serde_json::json!({
                                "invoice": invoice_str,
                                "amount_sats": amount_sats,
                                "deposit_id": hex::encode(deposit_id),
                                "payment_hash": hex::encode(payment_hash),
                                "cosign_required": true,
                                "cosigner_pubkey": r.get("cosigner_pubkey").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosigner_ledger_hash": r.get("cosigner_ledger_hash").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosign_signature": r.get("cosign_signature").and_then(|v| v.as_str()).unwrap_or(""),
                                "operator_pubkey": operator_pubkey_hex,
                                "operator_ledger_hash": operator_ledger_hash_hex,
                                "operator_signature": operator_signature_hex,
                            });
                            (true, Some(result.to_string()), None)
                        }
                        None => (
                            false,
                            None,
                            Some(
                                "Invoice co-signature required but no quorum member responded"
                                    .to_string(),
                            ),
                        ),
                    }
                } else {
                    let result = serde_json::json!({
                        "invoice": invoice_str,
                        "amount_sats": amount_sats,
                        "deposit_id": hex::encode(deposit_id),
                        "payment_hash": hex::encode(payment_hash),
                        "operator_pubkey": operator_pubkey_hex,
                        "operator_ledger_hash": operator_ledger_hash_hex,
                        "operator_signature": operator_signature_hex,
                    });
                    (true, Some(result.to_string()), None)
                }
            }
            Err(e) => {
                tracing::error!("Failed to create invoice: {}", e);
                (
                    false,
                    None,
                    Some(format!("Failed to create invoice: {}", e)),
                )
            }
        }
    }

    /// Process a pay_invoice request - pay Lightning invoice from deposit
    ///
    /// Uses LdkBackend to talk to the ldk-server sidecar (same as `deposits-node lightning pay`)
    ///
    /// Params:
    /// - descriptor: full miniscript expression that pays out the deposit
    /// - invoice: bolt11 invoice string
    /// - payment_hash: 32-byte hex (must match invoice)
    /// - amount_msats: amount in msats (must match invoice)
    /// - witness: DescriptorWitness authorizing the spend over the dep-17 InvoiceLock preimage
    pub(crate) async fn process_pay_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::messages::LedgerOperation;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Caller submits the full miniscript descriptor; identity is its hash.
        let (descriptor, deposit_id) = match super::deposits::parse_descriptor_param(request) {
            Ok(parts) => parts,
            Err(msg) => return (false, None, Some(msg)),
        };

        let invoice_str = match request.params.get("invoice").and_then(|v| v.as_str()) {
            Some(i) => i,
            None => return (false, None, Some("Missing invoice parameter".to_string())),
        };

        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                return (
                    false,
                    None,
                    Some("Missing payment_hash parameter".to_string()),
                )
            }
        };

        let amount_msat = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => {
                return (
                    false,
                    None,
                    Some("Missing amount_msats parameter".to_string()),
                )
            }
        };

        // The witness is the full descriptor satisfaction (a stack of
        // bytes per miniscript node). For pk(...) it's a single Schnorr
        // signature; for multi(2,A,B,C) it's three signatures plus
        // CMS placeholders, etc.
        let witness: DescriptorWitness = match request
            .params
            .get("witness")
            .ok_or_else(|| "Missing witness parameter".to_string())
            .and_then(|v| {
                serde_json::from_value::<DescriptorWitness>(v.clone())
                    .map_err(|e| format!("Invalid witness: {}", e))
            }) {
            Ok(w) => w,
            Err(e) => return (false, None, Some(e)),
        };

        // Parse payment_hash from client
        let mut payment_id = [0u8; 32];
        match hex::decode(payment_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => payment_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        }

        // Parse the BOLT11 invoice and verify it matches client's payment_hash and amount
        let invoice = match Bolt11Invoice::from_str(invoice_str) {
            Ok(inv) => inv,
            Err(e) => return (false, None, Some(format!("Invalid invoice: {}", e))),
        };

        let invoice_payment_hash = invoice.payment_hash();
        let invoice_hash_bytes: &[u8] = invoice_payment_hash.as_ref();
        if invoice_hash_bytes != payment_id {
            return (
                false,
                None,
                Some("payment_hash does not match invoice".to_string()),
            );
        }

        let invoice_amount = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_amount != amount_msat {
            return (
                false,
                None,
                Some("amount_msats does not match invoice".to_string()),
            );
        }

        // Witness crypto-verification against the descriptor used to
        // live here as a preflight; it now runs in `check_conformance`
        // when this InvoiceLock is staged.

        // Find the ledger and check deposit balance
        let ledger_id = &request.ledger_id;
        let ledger_arc = match self.handler.ledgers.lock().unwrap().get(ledger_id).cloned() {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Phase 5d: the wallet picks `nonce` (random/timestamp) and `expiry` (chain-tip
        // + margin) and signs the dep-17 operation preimage with them. The operator
        // must construct the InvoiceLock with the wallet's nonce/expiry so the
        // signature verifies. `sequence_number` is the invoice-flow ledger position
        // and isn't bound by the dep-17 preimage — operator picks it freely.
        let op_nonce = match request.params.get("nonce").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce parameter".to_string())),
        };
        let op_expiry = match request.params.get("expiry").and_then(|v| v.as_u64()) {
            Some(e) if e <= u32::MAX as u64 => e as u32,
            _ => return (false, None, Some("Missing or out-of-range expiry parameter".to_string())),
        };
        let sequence_number = {
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Deposit not found".to_string())),
            };

            if deposit.balance < amount_msat {
                return (
                    false,
                    None,
                    Some(format!(
                        "Insufficient balance: {} msat available, {} msat needed",
                        deposit.balance, amount_msat
                    )),
                );
            }

            ledger.next_sequence()
        };

        let lock_operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msat,
            payment_id,
            sequence_number,
            nonce: op_nonce,
            expiry: op_expiry,
            witness: witness.clone(),
        };

        // Commit the lock operation via staged flow
        if let Err(e) = self.commit_operation(ledger_id, lock_operation).await {
            return (false, None, Some(format!("Failed to lock funds: {}", e)));
        }

        tracing::info!(
            "Locked {} msat for payment {}",
            amount_msat,
            hex::encode(&payment_id[..8])
        );

        // Check for self-pay: if this invoice was created by us (exists in pending_invoices),
        // settle internally without touching LDK. This handles the case where a depositor
        // pays an invoice created for another depositor on the same operator.
        let self_pay = self
            .pending_invoices
            .lock()
            .unwrap()
            .contains_key(&payment_id);

        if self_pay {
            tracing::info!(
                "Self-pay detected for payment {}... — settling internally",
                hex::encode(&payment_id[..8])
            );

            // Look up the pending invoice to find the destination deposit
            let pending = self.pending_invoices.lock().unwrap().remove(&payment_id);
            self.save_pending_invoices();
            if let Some(pending) = pending {
                // We never route this payment through Lightning — both
                // sides are on this operator's books — but LDK *does*
                // know the preimage because it generated the invoice
                // when `make_invoice` called `bolt11-receive`. Pull it
                // via `get-payment-details <payment_hash>` (NOT
                // list-payments, which only enumerates OUTBOUND
                // payments and never finds receive-side invoices) so
                // the on-ledger InvoiceFulfill is real proof-of-payment
                // hashing to the BOLT11's payment_hash.
                let payment_hex = hex::encode(payment_id);
                let preimage = {
                    let cli = crate::lightning_backend::from_env();
                    match cli.get_payment_preimage(&payment_hex) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            tracing::warn!(
                                "Self-pay {}: LDK has no payment record for this hash; \
                                 committing zero-preimage InvoiceFulfill",
                                &payment_hex[..16]
                            );
                            [0u8; 32]
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Self-pay {}: get-payment-details failed: {}; \
                                 committing zero-preimage InvoiceFulfill",
                                &payment_hex[..16],
                                e
                            );
                            [0u8; 32]
                        }
                    }
                };

                // Fulfill the lock (debit sender)
                let fulfill_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let fulfill_operation = LedgerOperation::InvoiceFulfill {
                    deposit_id,
                    amount: amount_msat,
                    payment_id,
                    sequence_number: fulfill_sequence,
                    witness: witness.clone(),
                    preimage,
                };

                if let Err(e) = self.commit_operation(ledger_id, fulfill_operation).await {
                    return (
                        false,
                        None,
                        Some(format!("Failed to fulfill self-pay: {}", e)),
                    );
                }

                // Credit the destination deposit
                let credit_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let credit_operation = LedgerOperation::InvoiceCredit {
                    payment_hash: payment_id,
                    deposit_id: pending.deposit_id,
                    amount: amount_msat,
                    invoice_id: pending.invoice.clone(),
                    sequence_number: credit_sequence,
                    // Settlement-atomic wallet auth (DEP-07 §"Tiered receive")
                    // is pre-cosigned by the wallet during the receive
                    // negotiation, not synthesized here. Until that wallet
                    // flow lands (task #177), every operator-side credit is
                    // deterrence-only — fraud-proof recourse covers it.
                    wallet_authorization: None,
                };

                if let Err(e) = self.commit_operation(ledger_id, credit_operation).await {
                    tracing::error!("Failed to credit destination deposit: {}", e);
                }

                tracing::info!(
                    "Self-pay settled: {} msat from {} to {}",
                    amount_msat,
                    hex::encode(&deposit_id[..4]),
                    hex::encode(&pending.deposit_id[..4])
                );

                let result = serde_json::json!({
                    "payment_id": payment_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "amount_msat": amount_msat,
                    "preimage": hex::encode(preimage),
                    "status": "succeeded",
                    "self_pay": true,
                });
                return (true, Some(result.to_string()), None);
            }
        }

        // Pay invoice via LdkBackend, then wait synchronously for LDK to
        // settle. We return one Kind 20102 carrying the actual outcome
        // — preimage on success, error on failure — so the wallet
        // doesn't have to poll Kind 9100 ledger updates to learn what
        // happened. The auto-task remains as the crash-recovery path:
        // if the daemon dies between dispatch and resolve, the
        // open_invoice_lock survives on disk and gets reconciled
        // against LDK on the next periodic tick.
        let cli = crate::lightning_backend::from_env();
        match cli.pay_invoice(invoice_str) {
            Ok(_) => {
                tracing::info!(
                    "LDK payment dispatched for {}..., waiting for resolution",
                    hex::encode(&payment_id[..8])
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("already been initiated")
                    || err_str.contains("already initiated")
                {
                    // Cross-node self-pay (shared LDK node, invoice
                    // already known to LDK). Fall through to the
                    // resolution poll below — LDK already has it.
                    tracing::info!(
                        "Cross-node self-pay detected for {}..., polling LDK for resolution",
                        hex::encode(&payment_id[..8])
                    );
                } else {
                    tracing::warn!(
                        "LDK pay_invoice failed for {}...: {}, failing lock",
                        hex::encode(&payment_id[..8]),
                        e
                    );

                    let fail_sequence = {
                        let ledger = ledger_arc.read().unwrap();
                        ledger.next_sequence()
                    };
                    let fail_operation = LedgerOperation::InvoiceFail {
                        deposit_id,
                        amount: amount_msat,
                        payment_id,
                        sequence_number: fail_sequence,
                    };
                    if let Err(e2) = self.commit_operation(ledger_id, fail_operation).await {
                        tracing::error!("Failed to commit fail: {}", e2);
                    }
                    return (false, None, Some(format!("Payment failed: {}", e)));
                }
            }
        }

        // Poll LDK every second for up to 60s waiting for the payment
        // to resolve. Lightning typically settles within a couple of
        // seconds; the longer ceiling covers multi-hop retries. If we
        // hit the ceiling without resolution, return an error to the
        // wallet — auto_complete_outbound_payments will pick the lock
        // up and commit the right operation when LDK eventually
        // reports.
        let payment_hex = hex::encode(payment_id);
        let resolve_deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);
        let poll_interval = tokio::time::Duration::from_secs(1);
        let resolution = loop {
            if tokio::time::Instant::now() >= resolve_deadline {
                break None;
            }
            tokio::time::sleep(poll_interval).await;
            let payments = match cli.list_payments() {
                Ok(payments) => payments,
                Err(e) => {
                    tracing::debug!("list_payments error (will retry): {}", e);
                    continue;
                }
            };
            if let Some(p) = payments.iter().find(|p| p.id == payment_hex) {
                use crate::lightning_backend::PaymentStatus;
                match p.status {
                    PaymentStatus::Succeeded => break Some(Ok(p.preimage_hex.clone())),
                    PaymentStatus::Failed => break Some(Err(())),
                    PaymentStatus::Pending => continue,
                }
            }
        };

        match resolution {
            Some(Ok(preimage_hex)) => {
                // Resolve the preimage. The outbound `list-payments`
                // entry has it on a normal Lightning hop. On
                // cross-node self-pay (two operators sharing one LDK
                // node, A paying B's invoice), LDK shortcircuits
                // internally — outbound lands at status=succeeded but
                // `preimage: None` because no hop happened. The
                // preimage is on the receive-side BOLT11 record;
                // `get_payment_preimage` (= `get-payment-details`)
                // returns it.
                let mut preimage = [0u8; 32];
                let outbound_hex = preimage_hex.as_deref();
                let resolved = match outbound_hex {
                    Some(hex_str) => match hex::decode(hex_str) {
                        Ok(bytes) if bytes.len() == 32 => {
                            preimage.copy_from_slice(&bytes);
                            true
                        }
                        _ => false,
                    },
                    None => false,
                };
                if !resolved {
                    match cli.get_payment_preimage(&payment_hex) {
                        Ok(Some(p)) => {
                            preimage = p;
                            tracing::info!(
                                "pay_invoice {}: outbound had no preimage; \
                                 fell back to get-payment-details (cross-node self-pay)",
                                &payment_hex[..16]
                            );
                        }
                        Ok(None) => {
                            return (
                                false,
                                None,
                                Some(format!(
                                    "LDK reported succeeded but no preimage on either \
                                     list-payments or get-payment-details for {}",
                                    &payment_hex[..16]
                                )),
                            );
                        }
                        Err(e) => {
                            return (
                                false,
                                None,
                                Some(format!(
                                    "LDK preimage lookup failed for {}: {}",
                                    &payment_hex[..16],
                                    e
                                )),
                            );
                        }
                    }
                }

                // Sanity: sha256(preimage) must equal payment_id.
                // Cheap to compute, expensive to commit and roll back.
                {
                    use bitcoin::hashes::{sha256, Hash};
                    let computed: [u8; 32] =
                        *sha256::Hash::hash(&preimage).as_byte_array();
                    if computed != payment_id {
                        return (
                            false,
                            None,
                            Some(format!(
                                "LDK preimage doesn't hash to payment_hash for {}: \
                                 sha256(preimage)={} != payment_hash={}",
                                &payment_hex[..16],
                                hex::encode(computed),
                                payment_hex
                            )),
                        );
                    }
                }

                // Commit InvoiceFulfill with the real preimage so the
                // ledger record is also proof-of-payment. The witness
                // re-attaches the depositor's authorization that
                // InvoiceLock cached on `open_invoice_locks` — the
                // same signature still satisfies the descriptor over
                // the lock's dep-17 preimage.
                let (fulfill_sequence, lock_witness) = {
                    let ledger = ledger_arc.read().unwrap();
                    let witness = ledger
                        .state
                        .open_invoice_locks
                        .get(&payment_id)
                        .map(|l| l.witness.clone())
                        .unwrap_or_default();
                    (ledger.next_sequence(), witness)
                };
                let fulfill_op = LedgerOperation::InvoiceFulfill {
                    deposit_id,
                    amount: amount_msat,
                    payment_id,
                    sequence_number: fulfill_sequence,
                    witness: lock_witness,
                    preimage,
                };
                if let Err(e) = self.commit_operation(ledger_id, fulfill_op).await {
                    return (
                        false,
                        None,
                        Some(format!("Failed to commit InvoiceFulfill: {}", e)),
                    );
                }

                tracing::info!(
                    "Payment {}... fulfilled via LDK ({} msats)",
                    &payment_hex[..16],
                    amount_msat
                );

                let result = serde_json::json!({
                    "payment_id": payment_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "amount_msat": amount_msat,
                    "preimage": hex::encode(preimage),
                    "status": "succeeded",
                });
                (true, Some(result.to_string()), None)
            }
            Some(Err(())) => {
                let fail_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };
                let fail_op = LedgerOperation::InvoiceFail {
                    deposit_id,
                    amount: amount_msat,
                    payment_id,
                    sequence_number: fail_sequence,
                };
                if let Err(e) = self.commit_operation(ledger_id, fail_op).await {
                    tracing::error!("Failed to commit InvoiceFail: {}", e);
                }
                (
                    false,
                    None,
                    Some("Payment failed: LDK reported failure".to_string()),
                )
            }
            None => {
                // 60s without LDK reporting either way. Don't commit
                // anything — the open_invoice_lock stays on the
                // ledger and the auto-task will reconcile it.
                tracing::warn!(
                    "Payment {}... still pending after 60s; auto_complete_outbound_payments will reconcile",
                    &payment_hex[..16]
                );
                (
                    false,
                    None,
                    Some(
                        "Payment timeout: LDK didn't resolve in 60s. \
                         Run `deposits-wallet sync` later to pick up the eventual outcome."
                            .to_string(),
                    ),
                )
            }
        }
    }

    pub(crate) async fn process_cosign_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;

        tracing::info!(
            "Processing cosign_invoice request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return (false, None, Some("Missing payment_hash".to_string())),
        };
        let deposit_id_hex = match request.params.get("deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d.to_string(),
            None => return (false, None, Some("Missing deposit_id".to_string())),
        };
        let amount_msat = match request.params.get("amount_msat").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_msat".to_string())),
        };

        let payment_hash: [u8; 32] = match hex::decode(&payment_hash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        };
        let deposit_id: [u8; 16] = match hex::decode(&deposit_id_hex) {
            Ok(b) if b.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                a
            }
            _ => return (false, None, Some("Invalid deposit_id".to_string())),
        };

        // Find our member ledger hash (same lookup as cosign_offer)
        let member_ledger_hash: [u8; 32] = {
            let cached_key = self
                .cosign_member_cache
                .lock()
                .unwrap()
                .get(&request.ledger_id)
                .cloned();
            let member_key = if let Some(key) = cached_key {
                key
            } else {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found_key = None;
                for (ledger_key, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    if ledger.operator_key() != self.node_id {
                        continue;
                    }
                    let has_join = ledger
                        .state
                        .joined_quorums
                        .iter()
                        .any(|jq| jq.ledger_id == request.ledger_id);
                    if has_join {
                        found_key = Some(ledger_key.clone());
                        break;
                    }
                }
                drop(ledgers);
                match found_key {
                    Some(key) => {
                        self.cosign_member_cache
                            .lock()
                            .unwrap()
                            .insert(request.ledger_id.clone(), key.clone());
                        key
                    }
                    None => return (false, None, Some("Not a quorum member".to_string())),
                }
            };
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&member_key) {
                Some(arc) => arc
                    .read()
                    .unwrap()
                    .history
                    .last()
                    .map(|u| u.content_hash)
                    .unwrap_or([0u8; 32]),
                None => return (false, None, Some("Member ledger not found".to_string())),
            }
        };

        // Canonical signing message lives in
        // `deposits_protocol::invoice_cosign_signing_message` so verifiers
        // (wallet, fraud-proof verifier) reproduce the same hash without
        // duplicating the tagged-hash construction.
        let msg_hash = deposits_core::signature_utils::invoice_cosign_signing_message(
            &request.ledger_id,
            &payment_hash,
            &deposit_id,
            amount_msat,
            &member_ledger_hash,
        );

        use deposits_signer_api::{SigPurpose, SignContext};
        let sig = match self.handler.signer.bip340_sign(
            &SignContext::no_ledger(SigPurpose::InvoiceCosign),
            &msg_hash,
        ) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("invoice cosign sign: {}", e))),
        };

        tracing::info!(
            "Co-signed invoice {} for ledger {}...",
            &payment_hash_hex[..16],
            &request.ledger_id[..16]
        );

        let result = serde_json::json!({
            "cosign_signature": hex::encode(sig),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "cosigner_ledger_hash": hex::encode(member_ledger_hash),
        });
        (true, Some(result.to_string()), None)
    }

}
