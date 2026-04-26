//! Invoice request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    /// Process a make_invoice request - create Lightning invoice for deposit credit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning invoice`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - amount_sats: amount for the invoice
    /// - description: optional invoice description
    pub(crate) async fn process_make_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
        let deposit_pubkey_hex = match request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(pk) => pk,
            None => {
                return (
                    false,
                    None,
                    Some("Missing deposit_pubkey parameter".to_string()),
                )
            }
        };

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Check if deposit requires receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                    if deposit.receive_requires_sig {
                        use bitcoin::secp256k1::{schnorr::Signature, Message};
                        let recv_sig_hex = match request
                            .params
                            .get("receive_signature")
                            .and_then(|v| v.as_str())
                        {
                            Some(s) => s,
                            None => {
                                return (
                                    false,
                                    None,
                                    Some(
                                        "Deposit requires receive_signature for invoices"
                                            .to_string(),
                                    ),
                                )
                            }
                        };
                        let recv_sig = match hex::decode(recv_sig_hex)
                            .ok()
                            .and_then(|bytes| Signature::from_slice(&bytes).ok())
                        {
                            Some(sig) => sig,
                            None => {
                                return (false, None, Some("Invalid receive_signature".to_string()))
                            }
                        };
                        // Sign the deposit_id to authorize receiving
                        let recv_msg = Message::from_digest({
                            let mut h = [0u8; 32];
                            h[..16].copy_from_slice(&deposit_id);
                            h
                        });
                        let dest_pubkey = match hex::decode(deposit_pubkey_hex)
                            .ok()
                            .and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok())
                        {
                            Some(pk) => pk.x_only_public_key().0,
                            None => {
                                return (false, None, Some("Invalid deposit_pubkey".to_string()))
                            }
                        };
                        let secp = &self.secp;
                        if secp
                            .verify_schnorr(&recv_sig, &recv_msg, &dest_pubkey)
                            .is_err()
                        {
                            return (false, None, Some("Invalid receive_signature".to_string()));
                        }
                    }
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

        // Create invoice via LdkCli (same as `deposits-node lightning invoice`)
        let cli = LdkCli::from_env();

        match cli.create_invoice(amount_msat, description) {
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
                    "Created invoice for {}... amount={} sats, hash={}",
                    &deposit_pubkey_hex[..16.min(deposit_pubkey_hex.len())],
                    amount_sats,
                    hex::encode(&payment_hash[..8])
                );

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
                                "deposit_pubkey": deposit_pubkey_hex,
                                "deposit_id": hex::encode(deposit_id),
                                "payment_hash": hex::encode(payment_hash),
                                "cosign_required": true,
                                "cosigner_pubkey": r.get("cosigner_pubkey").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosigner_ledger_hash": r.get("cosigner_ledger_hash").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosign_signature": r.get("cosign_signature").and_then(|v| v.as_str()).unwrap_or(""),
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
                        "deposit_pubkey": deposit_pubkey_hex,
                        "deposit_id": hex::encode(deposit_id),
                        "payment_hash": hex::encode(payment_hash),
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
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning pay`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - invoice: bolt11 invoice string
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over payment message
    pub(crate) async fn process_pay_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};
        use deposits_core::messages::LedgerOperation;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
        let deposit_pubkey_hex = match request
            .params
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(pk) => pk,
            None => {
                return (
                    false,
                    None,
                    Some("Missing deposit_pubkey parameter".to_string()),
                )
            }
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

        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature parameter".to_string())),
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

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Parse pubkey for signature verification
        let deposit_pubkey = match hex::decode(deposit_pubkey_hex)
            .ok()
            .and_then(|bytes| bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok())
        {
            Some(pk) => pk,
            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
        };

        // Verify INVOICE signature (deposit_id, payment_hash, amount)
        let secp = Secp256k1::verification_only();
        let msg_hash = deposits_core::signature_utils::invoice_lock_signing_message(
            &deposit_id,
            &payment_id,
            amount_msat,
        );
        let msg = Message::from_digest(msg_hash);

        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (false, None, Some("Invalid signature format".to_string())),
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return (false, None, Some("Invalid signature".to_string())),
        };

        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from(deposit_pubkey);
        if secp.verify_schnorr(&signature, &msg, &xonly).is_err() {
            return (
                false,
                None,
                Some("Signature verification failed".to_string()),
            );
        }

        // Find the ledger and check deposit balance
        let ledger_id = &request.ledger_id;
        let ledger_arc = match self.handler.ledgers.lock().unwrap().get(ledger_id).cloned() {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
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

        // Create witness from signature
        let witness = DescriptorWitness {
            stack: vec![sig_bytes.clone()],
        };

        let lock_operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msat,
            payment_id,
            sequence_number,
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
                    preimage: [0u8; 32],
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
                    "payment_id": hex::encode(payment_id),
                    "deposit_pubkey": deposit_pubkey_hex,
                    "amount_msat": amount_msat,
                    "status": "succeeded",
                    "self_pay": true,
                });
                return (true, Some(result.to_string()), None);
            }
        }

        // Pay invoice via LdkCli — dispatch payment and return immediately.
        // The background auto_complete_outbound_payments task will poll LDK
        // and commit InvoiceFulfill or InvoiceFail.
        let cli = LdkCli::from_env();
        match cli.pay_invoice(invoice_str) {
            Ok(_) => {
                tracing::info!(
                    "LDK payment dispatched for {}..., will complete in background",
                    hex::encode(&payment_id[..8])
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                // "already initiated" means the invoice exists on the shared LDK node
                // (created by another operator). This is cross-node self-pay — the payment
                // will settle internally via LDK. Let auto_complete_outbound_payments handle it.
                if err_str.contains("already been initiated")
                    || err_str.contains("already initiated")
                {
                    tracing::info!("Cross-node self-pay detected for {}... (shared LDK node), will complete in background",
                        hex::encode(&payment_id[..8]));
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

        let result = serde_json::json!({
            "payment_id": hex::encode(payment_id),
            "deposit_pubkey": deposit_pubkey_hex,
            "amount_msat": amount_msat,
            "status": "pending",
        });
        (true, Some(result.to_string()), None)
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

        let secp = &self.secp;
        let msg = Message::from_digest(msg_hash);
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        tracing::info!(
            "Co-signed invoice {} for ledger {}...",
            &payment_hash_hex[..16],
            &request.ledger_id[..16]
        );

        let result = serde_json::json!({
            "cosign_signature": hex::encode(sig.serialize()),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "cosigner_ledger_hash": hex::encode(member_ledger_hash),
        });
        (true, Some(result.to_string()), None)
    }

}
