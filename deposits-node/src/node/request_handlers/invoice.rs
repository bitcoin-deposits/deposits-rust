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
    #[tracing::instrument(
        name = "make_invoice",
        skip_all,
        fields(ledger = %request.ledger_id, payment_hash = tracing::field::Empty)
    )]
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
                    let descriptor = ledgers.get(&request.ledger_id).and_then(|arc| {
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

        // Amount: prefer `amount_msats` (sub-sat capable — LN/BOLT11/LDK are all
        // msat-native, and our backend already takes amount_msat), falling back
        // to whole-sat `amount_sats` for older callers.
        let amount_msat = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
            Some(m) => m,
            None => match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
                Some(s) => s * 1000,
                None => {
                    return (
                        false,
                        None,
                        Some("Missing amount_msats or amount_sats parameter".to_string()),
                    )
                }
            },
        };
        if amount_msat == 0 {
            return (false, None, Some("amount must be > 0".to_string()));
        }
        // Whole-sat view, kept for response fields / back-compat (rounds down).
        let amount_sats = amount_msat / 1000;

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

        // NOTE: do not reconstruct amount_msat from amount_sats here — that would
        // re-floor sub-sat requests. amount_msat already holds the exact value.

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
        // BOLT-11 expiry. The payer's fund-lock is `invoice_expiry +
        // settlement_margin`, so a 24h backend default (ldk-server) made locks
        // needlessly long. Default to 1h and let the requester ask for a
        // different window, clamped to [1min, 24h]. The handler still rejects
        // (below, via max_transfer_timeout) if expiry + margin exceeds what the
        // quorum will co-sign.
        const DEFAULT_INVOICE_EXPIRY_SECS: u32 = 3600; // 1h
        const MIN_INVOICE_EXPIRY_SECS: u32 = 60;
        const MAX_INVOICE_EXPIRY_SECS: u32 = 86_400; // 24h
        let invoice_expiry_secs = request
            .params
            .get("expiry_secs")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(u32::MAX as u64) as u32)
            .unwrap_or(DEFAULT_INVOICE_EXPIRY_SECS)
            .clamp(MIN_INVOICE_EXPIRY_SECS, MAX_INVOICE_EXPIRY_SECS);
        let desc_owned = description.to_string();
        let dh_owned: Option<String> = description_hash.map(|s| s.to_string());
        let invoice_result = match tokio::time::timeout(
            std::time::Duration::from_secs(BACKEND_INVOICE_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                let cli = crate::lightning_backend::from_env();
                match dh_owned {
                    // Desc-hash (zap) invoices keep the backend default expiry.
                    Some(dh) => cli.create_invoice_with_desc_hash(amount_msat, &dh),
                    None => cli.create_invoice_with_expiry(
                        amount_msat,
                        &desc_owned,
                        invoice_expiry_secs,
                    ),
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

                // Tag the span with the payment_hash now that it's known — every
                // subsequent log line for this invoice (and across processes
                // that handle the same hash) carries it for correlation.
                tracing::Span::current().record("payment_hash", hex::encode(payment_hash).as_str());

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
                                arc.read().unwrap().history.last().map(|u| u.content_hash)
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
                            return (false, None, Some(format!("invoice cosign sign: {}", e)))
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
                                "amount_msat": amount_msat,
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
                        "amount_msat": amount_msat,
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
    /// Pre-flight quote for an outbound BOLT-11 (DEP-10 §Pay). Estimates the LN
    /// routing fee (real, via the backend's `estimate_routing_fee`; falls back
    /// to a 1% heuristic if the backend can't estimate) and adds the operator's
    /// margin (`invoice_fee_bps`). The wallet uses `total_fee_msats` to fund the
    /// `InvoiceLock.fee` budget instead of guessing. Advisory only — the routing
    /// cap on pay is what actually bounds the spend. Same handler the bridge
    /// uses for third-party quotes, just answered by the operator here.
    pub(crate) async fn process_quote_invoice_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        let invoice_str = match request
            .params
            .get("invoice")
            .or_else(|| request.params.get("bolt11"))
            .and_then(|v| v.as_str())
        {
            Some(i) => i,
            None => return (false, None, Some("Missing invoice parameter".to_string())),
        };
        let invoice = match Bolt11Invoice::from_str(invoice_str) {
            Ok(i) => i,
            Err(e) => return (false, None, Some(format!("Invalid invoice: {}", e))),
        };
        let amount_msat = match invoice.amount_milli_satoshis() {
            Some(a) if a > 0 => a,
            _ => return (false, None, Some("Invoice has no amount".to_string())),
        };

        // Real routing estimate; None → caller's heuristic fallback.
        let routing = match crate::lightning_backend::from_env().estimate_routing_fee(invoice_str) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::debug!("estimate_routing_fee fell back to heuristic: {}", e);
                None
            }
        };
        // Operator margin from the advertised invoice fee.
        let margin_bps = crate::operator_policy::OperatorPolicy::load(&self.data_dir)
            .ok()
            .flatten()
            .and_then(|p| p.invoice_fee_bps)
            .unwrap_or(0) as u64;
        let (routing_estimate_msats, margin_msats, total_fee_msats, estimation) =
            quote_fee_breakdown(amount_msat, routing, margin_bps);

        let quote_expiry_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 300;
        let result = serde_json::json!({
            "invoice_amount_msats": amount_msat,
            "routing_estimate_msats": routing_estimate_msats,
            "margin_msats": margin_msats,
            "total_fee_msats": total_fee_msats,
            "estimation": estimation,
            "quote_expiry_unix": quote_expiry_unix,
        });
        (true, Some(result.to_string()), None)
    }

    #[tracing::instrument(
        name = "pay_invoice",
        skip_all,
        fields(
            ledger = %request.ledger_id,
            payment_hash = request.params.get("payment_hash").and_then(|v| v.as_str()).unwrap_or(""),
        )
    )]
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

        // Operator fee budget the wallet attaches on TOP of the invoice amount,
        // covering LN routing + the operator's service margin (keep-the-spread).
        // Absent param = legacy amount-only lock (`fee_field` stays None so the
        // dep-16 preimage is byte-identical to what a pre-fee wallet signed).
        // Present = the wallet signed `Some(fee)` into the preimage; it's the
        // routing cap the operator pays under and the spread it retains.
        let fee_field: Option<u64> = request.params.get("fee_msats").and_then(|v| v.as_u64());
        let fee_msats = fee_field.unwrap_or(0);

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
            _ => {
                return (
                    false,
                    None,
                    Some("Missing or out-of-range expiry parameter".to_string()),
                )
            }
        };
        // The wallet must cover the operator's minimum fee (its advertised
        // invoice margin); a request that doesn't is rejected up front. The LN
        // routing cap is then `fee_msats`, so the operator never pays more
        // routing than the depositor budgeted (over-budget routes fail → the
        // lock resolves via InvoiceFail and the depositor is refunded).
        let min_fee_bps = crate::operator_policy::OperatorPolicy::load(&self.data_dir)
            .ok()
            .flatten()
            .and_then(|p| p.invoice_fee_bps)
            .unwrap_or(0) as u64;
        let min_fee_msats = amount_msat.saturating_mul(min_fee_bps) / 10_000;
        if fee_msats < min_fee_msats {
            return (
                false,
                None,
                Some(format!(
                    "Insufficient fee: {} msats provided, operator requires at least {} msats \
                     ({}bps of {} msats)",
                    fee_msats, min_fee_msats, min_fee_bps, amount_msat
                )),
            );
        }

        let sequence_number = {
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Deposit not found".to_string())),
            };

            // Must cover the invoice amount AND the fee budget (the wallet is
            // required to include more than the invoice amount).
            let needed = amount_msat + fee_msats;
            if deposit.balance < needed {
                return (
                    false,
                    None,
                    Some(format!(
                        "Insufficient balance: {} msat available, {} msat needed",
                        deposit.balance, needed
                    )),
                );
            }

            ledger.next_sequence()
        };

        // Fund-lock timeout (block height): the operator's deadline to release
        // the lock if the payment never resolves. NOT the dep-17 signature
        // `expiry` above — the depositor doesn't sign this; the node sets it to
        // a self-interested minimum (just past the invoice's own expiry plus a
        // settlement margin) and caps it at the strictest quorum member's
        // `max_transfer_timeout_blocks`. If the invoice's expiry is so long that
        // even the minimum lock would exceed the cap, reject up front rather
        // than building a lock the quorum won't co-sign.
        // Settlement margin past the invoice's expiry. The deposits ledger is
        // off-chain, so this is NOT a chain-settlement buffer — it's the
        // dispute/recovery window (a confiscation playing out, or the operator
        // re-establishing its view of an in-flight pay after a crash). Hours,
        // not the legacy 144-block (~1 day) round number. Operator-tunable.
        let settlement_margin_blocks = crate::operator_policy::OperatorPolicy::load(&self.data_dir)
            .ok()
            .flatten()
            .and_then(|p| p.invoice_lock_margin_blocks)
            .unwrap_or(36); // ~6h
        let timeout_height = {
            let ledger = ledger_arc.read().unwrap();
            // Anchor the fund-lock timeout to the LIVE chain tip, not the
            // ledger's last-stamped op height (which is frozen on a ledger with
            // no fresh on-chain ops). auto_complete_outbound_payments judges
            // expiry against the live tip too; anchoring here to a stale height
            // would make the lock look already-expired and fail in-flight pays.
            let current_block = self
                .wallet
                .get_block_height()
                .ok()
                .filter(|&h| h > 0)
                .unwrap_or_else(|| ledger.history.last().map(|u| u.block_height).unwrap_or(0));
            let max_timeout = ledger
                .state
                .quorum_members
                .iter()
                .filter_map(|m| m.max_transfer_timeout_blocks)
                .min()
                .unwrap_or(1008); // default ~1 week
                                  // BOLT11 expiry window (seconds) → blocks at ~10 min/block.
            let invoice_expiry_blocks = (invoice.expiry_time().as_secs() / 600) as u32;
            let needed = invoice_expiry_blocks.saturating_add(settlement_margin_blocks);
            if needed > max_timeout {
                return (
                    false,
                    None,
                    Some(format!(
                        "Invoice expiry too long: would need a {}-block fund lock, but the \
                         quorum's maximum is {} blocks. Ask for an invoice with a shorter expiry.",
                        needed, max_timeout
                    )),
                );
            }
            // current_block can be 0 pre-sync; still produce a bounded height.
            current_block.saturating_add(needed)
        };

        let lock_operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msat,
            payment_id,
            sequence_number,
            nonce: op_nonce,
            expiry: op_expiry,
            timeout_height: Some(timeout_height),
            fee: fee_field,
            witness: witness.clone(),
            commitment: None,
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
                    commitment: None,
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
                    commitment: None,
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
        // Cap routing at the depositor's fee budget so the operator never pays
        // more routing than was locked. fee=0 (legacy/None) → uncapped, the
        // backend's own default applies.
        let pay_result = if fee_msats > 0 {
            cli.pay_invoice_with_fee_cap(invoice_str, fee_msats)
        } else {
            cli.pay_invoice(invoice_str)
        };
        match pay_result {
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
                        payment_id,
                        sequence_number: fail_sequence,
                        commitment: None,
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
        // Shared response for "LDK resolved the payment but we can't produce a
        // verifiable preimage yet" (no preimage surfaced, lookup error, or a
        // preimage that doesn't hash). The InvoiceLock stays open and
        // auto_complete_outbound reconciles it on a later poll — so tell the
        // caller to WAIT, not retry: a retry could double-pay a payment that
        // actually settled.
        let pending_reconcile = || -> (bool, Option<String>, Option<String>) {
            (
                false,
                None,
                Some(
                    "Payment is still reconciling on the operator — do not retry. \
                     Run `deposits-wallet sync` shortly to pick up the final outcome."
                        .to_string(),
                ),
            )
        };

        let payment_hex = hex::encode(payment_id);
        let resolve_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);
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
                    // Cross-node self-pay: the preimage lives on the receive-side
                    // BOLT11 record (`get-payment-details`), which lands a beat
                    // after the outbound flips to Succeeded. Poll for it within the
                    // remaining 60s budget rather than bailing to "reconciling" on
                    // the first miss — pay_invoice should block until it can return
                    // the final outcome, not punt a just-settled payment to
                    // auto_complete_outbound.
                    loop {
                        match cli.get_payment_preimage(&payment_hex) {
                            Ok(Some(p)) => {
                                preimage = p;
                                tracing::info!(
                                    "pay_invoice {}: outbound had no preimage; \
                                     fell back to get-payment-details (cross-node self-pay)",
                                    &payment_hex[..16]
                                );
                                break;
                            }
                            Ok(None) | Err(_) => {
                                if tokio::time::Instant::now() >= resolve_deadline {
                                    tracing::warn!(
                                        "pay_invoice {}: succeeded but no preimage on \
                                         get-payment-details within budget — leaving the \
                                         InvoiceLock open for auto_complete_outbound",
                                        &payment_hex[..16]
                                    );
                                    return pending_reconcile();
                                }
                                tokio::time::sleep(poll_interval).await;
                            }
                        }
                    }
                }

                // Sanity: sha256(preimage) must equal payment_id.
                // Cheap to compute, expensive to commit and roll back.
                {
                    use bitcoin::hashes::{sha256, Hash};
                    let computed: [u8; 32] = *sha256::Hash::hash(&preimage).as_byte_array();
                    if computed != payment_id {
                        // LDK reported the payment succeeded but the preimage it
                        // gave us doesn't hash to the payment_hash. Don't commit a
                        // guaranteed-invalid InvoiceFulfill, and — critically — don't
                        // return a hard error: the lock is still open and the payment
                        // may have actually settled, so a "failed" response could make
                        // the wallet retry and double-pay. Leave it for
                        // auto_complete_outbound (which re-checks and can pick up a
                        // valid preimage on a later poll), and tell the caller to wait.
                        tracing::warn!(
                            "pay_invoice {}: LDK preimage doesn't hash to payment_hash — \
                             leaving lock for auto_complete_outbound. \
                             sha256(preimage)={} != payment_hash={}",
                            &payment_hex[..16],
                            hex::encode(computed),
                            payment_hex
                        );
                        return pending_reconcile();
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
                    commitment: None,
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
                    payment_id,
                    sequence_number: fail_sequence,
                    commitment: None,
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

/// Pure quote math for `quote_invoice`. `routing = Some(real estimate)` from the
/// backend, or `None` → a flat 1%-of-amount heuristic fallback. Margin is the
/// operator's `invoice_fee_bps` applied to the invoice amount. Returns
/// `(routing_estimate, margin, total, estimation)` where estimation is "real"
/// when the backend produced the figure and "heuristic" otherwise.
fn quote_fee_breakdown(
    amount_msat: u64,
    routing: Option<u64>,
    margin_bps: u64,
) -> (u64, u64, u64, &'static str) {
    let (routing_estimate, estimation) = match routing {
        Some(f) => (f, "real"),
        None => (amount_msat / 100, "heuristic"),
    };
    let margin = amount_msat.saturating_mul(margin_bps) / 10_000;
    (
        routing_estimate,
        margin,
        routing_estimate + margin,
        estimation,
    )
}

#[cfg(test)]
mod quote_tests {
    use super::quote_fee_breakdown;

    #[test]
    fn real_estimate_plus_margin() {
        // 200_000 msat invoice, real 850 routing, 20 bps margin (= 400).
        let (routing, margin, total, est) = quote_fee_breakdown(200_000, Some(850), 20);
        assert_eq!(routing, 850);
        assert_eq!(margin, 400);
        assert_eq!(total, 1250);
        assert_eq!(est, "real");
    }

    #[test]
    fn heuristic_fallback_is_one_percent() {
        // No backend estimate → routing = 1% of amount; margin still applies.
        let (routing, margin, total, est) = quote_fee_breakdown(200_000, None, 20);
        assert_eq!(routing, 2_000, "1% of 200_000");
        assert_eq!(margin, 400);
        assert_eq!(total, 2_400);
        assert_eq!(est, "heuristic");
    }

    #[test]
    fn zero_margin_when_operator_unset() {
        let (routing, margin, total, est) = quote_fee_breakdown(50_000, Some(120), 0);
        assert_eq!((routing, margin, total, est), (120, 0, 120, "real"));
    }
}
