//! Transfer request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    /// Process a withdrawal request from a depositor
    ///
    /// Params:
    /// - descriptor: full miniscript expression that pays out the deposit
    /// - address: destination Bitcoin address
    /// - amount_sats: amount to withdraw
    /// - fee_sats: fee for the withdrawal transaction
    /// - nonce: hex-encoded 32-byte nonce
    /// - witness: DescriptorWitness over `withdrawal_signing_message`
    pub(crate) async fn process_withdraw_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing withdraw request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Caller submits the descriptor; identity is its hash.
        let (descriptor, deposit_id) = match super::deposits::parse_descriptor_param(request) {
            Ok(parts) => parts,
            Err(msg) => return (false, None, Some(msg)),
        };

        let address = match request.params.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => return (false, None, Some("Missing address".to_string())),
        };
        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_sats".to_string())),
        };
        let fee_sats = match request.params.get("fee_sats").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee_sats".to_string())),
        };
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid nonce (must be 32 bytes hex)".to_string()),
                )
            }
        };

        // Witness authorizes the withdrawal under the descriptor.
        let depositor_witness: DescriptorWitness = match request
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

        // Witness crypto-verification used to live here as a preflight
        // that called `descriptor::verify_witness`. It's now done by
        // `check_conformance` when the operation is staged — the
        // handler keeps the JSON parse above so requests with
        // malformed witness shapes still fail fast.

        // Find the ledger
        let (reserves_id, _ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Lock the withdrawal with co-signing
        match self
            .lock_withdrawal(
                &reserves_id,
                deposit_id,
                address.to_string(),
                amount_sats,
                fee_sats,
                nonce,
                depositor_witness,
                None, // no memo
            )
            .await
        {
            Ok(lock_result) => {
                let withdrawal_id = lock_result.withdrawal.withdrawal_id;
                let result = serde_json::json!({
                    "status": "locked",
                    "withdrawal_id": hex::encode(withdrawal_id),
                    "message": "Withdrawal locked. Will be broadcast after lock period.",
                });
                tracing::info!("Withdrawal locked: {}", hex::encode(&withdrawal_id[..8]));
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Withdrawal failed: {}", e);
                (false, None, Some(format!("Withdrawal failed: {}", e)))
            }
        }
    }

    /// Process a transfer_lock request - lock funds for conditional transfer
    pub(crate) async fn process_transfer_lock_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::schnorr::Signature;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::types::DescriptorWitness;

        tracing::debug!(
            "Processing transfer_lock request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };
        let source_id_hex = match request
            .params
            .get("source_deposit_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return (false, None, Some("Missing source_deposit_id".to_string())),
        };
        let dest_id_hex = match request
            .params
            .get("destination_deposit_id")
            .and_then(|v| v.as_str())
        {
            Some(d) => d,
            None => {
                return (
                    false,
                    None,
                    Some("Missing destination_deposit_id".to_string()),
                )
            }
        };
        let amount_msats = match request.params.get("amount").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount".to_string())),
        };
        let fee_msats = match request.params.get("fee").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee".to_string())),
        };
        let completion_script = match request
            .params
            .get("completion_script")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return (false, None, Some("Missing completion_script".to_string())),
        };
        let timeout_height = match request
            .params
            .get("timeout_height")
            .and_then(|v| v.as_u64())
        {
            Some(t) => t as u32,
            None => return (false, None, Some("Missing timeout_height".to_string())),
        };
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature".to_string())),
        };

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid nonce".to_string())),
        };

        // Parse deposit IDs
        let mut source_deposit_id = [0u8; 16];
        match hex::decode(source_id_hex) {
            Ok(bytes) if bytes.len() == 16 => source_deposit_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid source_deposit_id".to_string())),
        }

        let mut destination_deposit_id = [0u8; 16];
        match hex::decode(dest_id_hex) {
            Ok(bytes) if bytes.len() == 16 => destination_deposit_id.copy_from_slice(&bytes),
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid destination_deposit_id".to_string()),
                )
            }
        }

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse signature
        let signature = match hex::decode(signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
        {
            Some(sig) => sig,
            None => return (false, None, Some("Invalid signature".to_string())),
        };

        // amount_msats and fee_msats already parsed from request

        // Get ledger and verify source deposit exists
        let ledger_id = &request.ledger_id;
        // Block-scoped to keep the ledger lookup tight; we no longer
        // need the descriptor (conformance does the witness check at
        // stage time) but the block still does the deposit-exists
        // and timeout-height preflight validations.
        let _ = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", ledger_id)),
                    )
                }
            };
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&source_deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Source deposit not found".to_string())),
            };

            // Validate timeout_height against max_transfer_timeout_blocks (strictest quorum member)
            let max_timeout = ledger
                .state
                .quorum_members
                .iter()
                .filter_map(|m| m.max_transfer_timeout_blocks)
                .min()
                .unwrap_or(1008); // default ~1 week
            let current_block = ledger.history.last().map(|u| u.block_height).unwrap_or(0);
            if current_block > 0 && timeout_height > current_block.saturating_add(max_timeout) {
                return (
                    false,
                    None,
                    Some(format!(
                        "timeout_height {} exceeds max: current_block {} + max_timeout {} = {}",
                        timeout_height,
                        current_block,
                        max_timeout,
                        current_block.saturating_add(max_timeout)
                    )),
                );
            }

            // Validate fee against deposit's transfer fee schedule (all in msats)
            let expected_fee = deposit.transfer_fees.calculate_fee(amount_msats);
            if fee_msats != expected_fee {
                return (
                    false,
                    None,
                    Some(format!(
                    "Fee mismatch: expected {} msats (fixed={} + {}bps on {} msats), got {} msats",
                    expected_fee, deposit.transfer_fees.fixed_msats,
                    deposit.transfer_fees.rate_bps, amount_msats, fee_msats
                )),
                );
            }

            // Check sufficient balance
            let total = amount_msats + fee_msats;
            if deposit.balance < total {
                let balance_json = format!("{{\"balance_msats\":{}}}", deposit.balance);
                return (
                    false,
                    Some(balance_json),
                    Some(format!(
                        "Insufficient balance: {} msats available, {} msats needed",
                        deposit.balance, total
                    )),
                );
            }

        };

        // Check destination deposit balance limit
        if let Some(err) = self.check_deposit_balance_limit(
            &request.ledger_id,
            &destination_deposit_id,
            amount_msats,
        ) {
            return (false, None, Some(err));
        }

        // Build the witness from the request's signature; crypto
        // verification against the source deposit's descriptor happens
        // via `check_conformance` when this TransferLock is staged.
        let witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };

        // Check if destination deposit requires a receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(dest_deposit) = ledger.state.deposits.get(&destination_deposit_id) {
                    if dest_deposit.receive_requires_sig {
                        // Verify receive signature from destination deposit key
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
                                        "Destination deposit requires receive_signature"
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
                        // Destination descriptor signs the transfer_id to authorize receiving
                        let recv_witness = DescriptorWitness {
                            stack: vec![recv_sig.serialize().to_vec()],
                        };
                        let tip = self.wallet.get_block_height().unwrap_or(0);
                        match deposits_core::descriptor::verify_witness(&dest_deposit.descriptor, &recv_witness, &transfer_id, tip) {
                            Ok(true) => {},
                            Ok(false) => return (false, None, Some("Invalid receive_signature: does not satisfy destination descriptor".to_string())),
                            Err(e) => return (false, None, Some(format!("Receive signature verification failed: {}", e))),
                        }
                    }
                }
            }
        }

        // Create and append the operation (amount_msats/fee_msats computed above in fee validation)
        let witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };
        let operation = LedgerOperation::TransferLock {
            transfer_nonce: nonce,
            source_deposit_id,
            destination_deposit_id,
            amount: amount_msats,
            fee: fee_msats,
            completion_script: completion_script.to_string(),
            timeout_height,
            transfer_id,
            // phase 3 TODO: thread deposit.last_op_nonce + 1 and a real expiry.
            nonce: 0,
            expiry: u32::MAX,
            witness,
        };

        // Append operation (applies state changes: deducts balance, adds to locked)
        let t_append = std::time::Instant::now();
        {
            // Commit via staged flow — no state mutation until signing succeeds
            match self.commit_operation(ledger_id, operation).await {
                Ok(_) => {}
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("Failed to commit transfer_lock: {}", e)),
                    );
                }
            }
        }
        let append_elapsed = t_append.elapsed();

        tracing::debug!("Transfer locked: {}", hex::encode(&transfer_id[..8]));
        tracing::debug!("[PROFILE] transfer_lock: {:?}", append_elapsed);
        (
            true,
            Some(
                serde_json::json!({
                    "transfer_id": transfer_id_hex,
                    "amount": amount_msats,
                    "fee": fee_msats,
                    "message": "Transfer locked successfully"
                })
                .to_string(),
            ),
            None,
        )
    }

    /// Process a transfer_complete request - complete a transfer by revealing preimage
    pub(crate) async fn process_transfer_complete_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::types::DescriptorWitness;

        tracing::debug!(
            "Processing transfer_complete request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract parameters
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let preimage_hex = match request.params.get("preimage").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return (false, None, Some("Missing preimage".to_string())),
        };

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse preimage
        let preimage: Vec<u8> = match hex::decode(preimage_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => {
                return (
                    false,
                    None,
                    Some("Invalid preimage (must be 32 bytes)".to_string()),
                )
            }
        };

        // Verify the preimage matches the hash in the pending transfer
        let ledger_id = &request.ledger_id;
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", ledger_id)),
                    )
                }
            };
            let ledger = ledger_arc.read().unwrap();

            let pending = match ledger.state.pending_transfers.get(&transfer_id) {
                Some(p) => p,
                None => return (false, None, Some("Pending transfer not found".to_string())),
            };

            // Verify preimage: hash it and check against completion_script
            // completion_script is like "sha256(abc123...)"
            if pending.completion_script.starts_with("sha256(") {
                let expected_hash_hex =
                    &pending.completion_script[7..pending.completion_script.len() - 1];
                let expected_hash = match hex::decode(expected_hash_hex) {
                    Ok(h) => h,
                    Err(_) => {
                        return (
                            false,
                            None,
                            Some("Invalid hash in completion_script".to_string()),
                        )
                    }
                };

                use bitcoin::hashes::{sha256, Hash};
                let actual_hash = sha256::Hash::hash(&preimage);
                if actual_hash.as_byte_array()[..] != expected_hash[..] {
                    return (
                        false,
                        None,
                        Some("Preimage does not match hash".to_string()),
                    );
                }
            } else {
                return (
                    false,
                    None,
                    Some("Only sha256() completion scripts supported".to_string()),
                );
            }
        }

        // Capture pending transfer info before appending (needed for rollback).
        // The lock was released between the check above and this block, so the
        // ledger could in principle have been removed by another thread —
        // re-check rather than unwrap.
        let pending_transfer_backup = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger disappeared mid-request: {}", ledger_id)),
                    )
                }
            };
            let ledger = ledger_arc.read().unwrap();
            ledger.state.pending_transfers.get(&transfer_id).cloned()
        };

        // Create and append the operation
        let script_witness = DescriptorWitness {
            stack: vec![preimage],
        };
        let operation = LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        };

        // Commit via staged flow
        match self.commit_operation(ledger_id, operation).await {
            Ok(_) => {}
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("Failed to commit transfer_complete: {}", e)),
                );
            }
        }

        crate::metrics::record_transfer_completed(&request.ledger_id);
        tracing::debug!("Transfer completed: {}", hex::encode(&transfer_id[..8]));
        let (completed_amount, completed_fee) = pending_transfer_backup
            .as_ref()
            .map(|p| (p.amount, p.fee))
            .unwrap_or((0, 0));
        (
            true,
            Some(
                serde_json::json!({
                    "transfer_id": transfer_id_hex,
                    "amount": completed_amount,
                    "fee": completed_fee,
                    "message": "Transfer completed successfully"
                })
                .to_string(),
            ),
            None,
        )
    }

}
