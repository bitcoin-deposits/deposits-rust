use super::*;

impl Node {
    /// Check if adding `additional_msats` to a ledger's obligations would exceed
    /// either the reserves limit or 2x the smallest quorum member's collateral commitment.
    ///
    /// Returns None if OK, or Some(error_message) if either limit would be exceeded.
    pub(crate) fn check_collateral_obligation_limit(
        &self,
        ledger_id: &str,
        additional_msats: u64,
    ) -> Option<String> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = match ledgers.get(ledger_id) {
            Some(l) => l.clone(),
            None => return None,
        };
        let ledger = ledger_arc.read().unwrap();

        // All deposits (including collateral) count toward reserves usage
        let all_deposits: u64 = ledger
            .state
            .deposits
            .values()
            .map(|d| d.balance + d.locked_balance)
            .sum();
        let new_total_all = all_deposits.saturating_add(additional_msats);

        // Check reserves limit: reserves cover everything (including collateral deposits)
        let reserves_limit_msats = ledger.state.reserves_amount;
        if reserves_limit_msats > 0 && new_total_all > reserves_limit_msats {
            return Some(format!(
                "Would exceed reserves: {} + {} = {} msats > {} msats (reserves {} msats)",
                all_deposits,
                additional_msats,
                new_total_all,
                reserves_limit_msats,
                ledger.state.reserves_amount
            ));
        }

        // Check collateral limit: total obligations <= collateral_amount
        let collateral = ledger.state.total_collateral();
        if collateral > 0 && new_total_all > collateral {
            return Some(format!(
                "Would exceed collateral: {} + {} = {} msats > {} msats (collateral)",
                all_deposits, additional_msats, new_total_all, collateral
            ));
        }

        None
    }

    /// Check if crediting `additional_msats` to `deposit_id` on `ledger_id` would
    /// exceed the per-deposit balance limit (MAX_DEPOSIT_BALANCE_MSATS).
    /// Returns an error string if the limit would be exceeded, None if ok.
    pub(crate) fn check_deposit_balance_limit(
        &self,
        ledger_id: &str,
        deposit_id: &[u8; 16],
        additional_msats: u64,
    ) -> Option<String> {
        let limit = self.max_deposit_balance_msats;
        if limit == 0 {
            return None; // Unlimited
        }

        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = match ledgers.get(ledger_id) {
            Some(l) => l.clone(),
            None => return None,
        };
        let ledger = ledger_arc.read().unwrap();

        let current_balance = ledger
            .state
            .deposits
            .get(deposit_id)
            .map(|d| d.balance + d.locked_balance)
            .unwrap_or(0);
        let new_balance = current_balance.saturating_add(additional_msats);

        if new_balance > limit {
            return Some(format!(
                "Would exceed deposit balance limit: {} + {} = {} msats > {} msats",
                current_balance, additional_msats, new_balance, limit
            ));
        }

        None
    }

    /// Build canonical signing data for invoice co-signatures.
    ///
    /// The signing data format is:
    /// `ledger_id || payment_hash || deposit_id || amount_msat`
    ///
    /// This data is then hashed using BIP-340 tagged hashing with tag "deposits/invoice_cosign"
    /// and combined with the member's ledger hash before signing.
    pub(crate) fn build_invoice_signing_data(
        ledger_id: &str,
        payment_hash: &[u8; 32],
        deposit_id: &[u8; 16],
        amount_msat: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(ledger_id.as_bytes());
        data.extend_from_slice(payment_hash);
        data.extend_from_slice(deposit_id);
        data.extend_from_slice(&amount_msat.to_le_bytes());
        data
    }

    /// Build canonical signing data for deposit offer co-signatures.
    ///
    /// The signing data format is:
    /// `ledger_id || offer_id || operator_id_x || len(funding_address) || funding_address || deadline_block`
    ///
    /// This data is then hashed using BIP-340 tagged hashing with tag "deposits/offer_cosign"
    /// and combined with the member's ledger hash before signing.
    pub(crate) fn build_offer_signing_data(
        ledger_id: &str,
        offer_id: &[u8; 32],
        operator_id: &PublicKey,
        funding_address: &str,
        deadline_block: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // ledger_id (64 hex chars = 32 bytes when decoded, but we use raw hex bytes for simplicity)
        data.extend_from_slice(ledger_id.as_bytes());

        // offer_id (32 bytes)
        data.extend_from_slice(offer_id);

        // operator_id x-coordinate only (32 bytes - excludes the 02/03 prefix)
        data.extend_from_slice(&operator_id.serialize()[1..]);

        // funding_address length (1 byte) + address bytes
        let addr_bytes = funding_address.as_bytes();
        data.push(addr_bytes.len() as u8);
        data.extend_from_slice(addr_bytes);

        // deadline_block (4 bytes, little-endian)
        data.extend_from_slice(&deadline_block.to_le_bytes());

        data
    }

    /// Sign an update with co-signature from a quorum member, then broadcast.
    ///
    /// This implements the "Porcupine Dance" signing order:
    /// 1. Partner (quorum member) signs (update content || their_ledger_hash) with ECDSA
    /// 2. Operator signs (content + cosign_signature) with Schnorr
    ///
    /// Co-signature behavior:
    /// - Before reserves rotation: Falls back to operator-only if no quorum members
    /// - After reserves rotation: Co-signatures are REQUIRED (fails if none available)
    ///
    /// # Arguments
    /// * `ledger_id` - The ledger_id (hash or reserves address) identifying our ledger
    ///
    /// # Returns
    /// The Nostr event ID of the broadcast update
    /// Acquire the per-ledger staging lock. Only one update can be in-flight at a time.
    pub(crate) async fn acquire_staging_lock(
        &self,
        ledger_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.staging_locks.lock().unwrap();
            locks
                .entry(ledger_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// The single correct way to create a new ledger update as an operator.
    ///
    /// 1. Stage: validate + build update (no state changes)
    /// 2. Cosign: request cosignature from quorum (if active)
    /// 3. Operator sign: sign the update (including cosign data)
    /// 4. Persist: write to disk first (crash safety)
    /// 5. Apply: modify ledger state + push to history
    /// 6. Broadcast: publish to relays
    pub async fn commit_operation(
        &self,
        ledger_id: &str,
        operation: deposits_core::messages::LedgerOperation,
    ) -> Result<String, Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Keypair;
        use deposits_core::ledger::StagedUpdate;

        // Acquire per-ledger lock — one update at a time
        let _lock = self.acquire_staging_lock(ledger_id).await;

        let block_height = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // 1. Stage: validate + build, no state changes
        let mut staged: StagedUpdate = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();
            let ledger = arc.read().unwrap();
            ledger
                .stage_operation(operation, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Stage failed: {}", e)))?
        };

        // 2. Cosign (if quorum active — collect majority cosignatures)
        let quorum_active = self.is_quorum_active(ledger_id);
        if quorum_active {
            let entries = self.request_cosign(ledger_id, &staged.update).await?;
            // Sort by pubkey and set on update
            let mut sorted = entries;
            sorted.sort_by(|a, b| {
                a.cosigner_pubkey
                    .serialize()
                    .cmp(&b.cosigner_pubkey.serialize())
            });
            staged.update.cosignatures = sorted;
            staged.update.cosigner_pubkey = None;
            staged.update.member_ledger_hash = None;
            staged.update.cosign_signature = [0u8; 64];
            staged.update.current_hash = staged.update.compute_hash();
        }

        // 3. Operator sign using operator_signing_data() (covers content + all cosignatures)
        {
            let secp = &self.secp;
            let data = staged.update.operator_signing_data();
            let hash = sha256::Hash::hash(&data);
            let msg = bitcoin::secp256k1::Message::from_digest(*hash.as_byte_array());
            let keypair = Keypair::from_secret_key(secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);
            staged.update.operator_signature = sig.serialize();
        }

        // 4. Apply state changes (persist happens via dirty_ledgers after commit)
        let update_clone = staged.update.clone();
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();
            let mut ledger = arc.write().unwrap();
            ledger
                .commit_staged(staged)
                .map_err(|e| Error::Protocol(format!("Commit failed: {}", e)))?;
        }

        // 5. Persist to disk immediately (crash safety — before broadcast)
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger after commit: {}", e);
        }

        // 6. Broadcast
        let event_id = self
            .nostr
            .broadcast_ledger_update(&update_clone)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to broadcast update seq={}: {}",
                    update_clone.sequence_number,
                    e
                );
                String::new()
            });

        tracing::info!(
            "Committed seq={} for ledger {}... (cosigned={}, event={})",
            update_clone.sequence_number,
            &ledger_id[..16.min(ledger_id.len())],
            quorum_active,
            if event_id.len() > 16 {
                &event_id[..16]
            } else {
                &event_id
            },
        );

        Ok(event_id)
    }

    pub async fn sign_and_broadcast(&self, ledger_id: &str) -> Result<String, Error> {
        let sab_start = std::time::Instant::now();

        // Check if reserves have been rotated to quorum (co-signatures become required)
        let quorum_active = self.is_quorum_active(ledger_id);

        // Get the ledger info we need
        let (has_quorum_members, update_clone) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
            let ledger = ledger_arc.read().unwrap();

            let has_quorum_members = !ledger.state.quorum_members.is_empty();

            // Clone the last update for co-signing
            let update_clone = ledger
                .history
                .last()
                .ok_or_else(|| Error::Protocol("No update to sign".to_string()))?
                .clone();

            (has_quorum_members, update_clone)
        };

        // If no quorum members and no rotation yet, fall back to operator-only signature
        if !has_quorum_members {
            if quorum_active {
                metrics::record_sign_and_broadcast("error_no_quorum", sab_start.elapsed());
                return Err(Error::Protocol(
                    "Reserves have been rotated but no quorum members available - cannot sign"
                        .to_string(),
                ));
            }
            tracing::debug!("No quorum members yet, using operator-only signature");
            let result = self.operator_sign_persist_broadcast(ledger_id).await;
            metrics::record_sign_and_broadcast("success_no_cosign", sab_start.elapsed());
            return result;
        }

        // Before reserves rotation, co-signatures are optional — skip the cosign
        // round-trip entirely to avoid blocking the event loop (each attempt holds
        // the run loop for 500ms, causing cascading timeouts under load).
        if !quorum_active {
            tracing::debug!(
                "Pre-rotation: skipping optional co-sign, using operator-only signature"
            );
            let result = self.operator_sign_persist_broadcast(ledger_id).await;
            metrics::record_sign_and_broadcast("success_skip_cosign", sab_start.elapsed());
            return result;
        }

        // Send multicast co-sign request - first responder wins
        // Retry up to 5 times since responses can be missed during polling gaps
        let max_attempts = 5;
        let mut last_error = None;
        let cosign_start = std::time::Instant::now();

        for attempt in 1..=max_attempts {
            let attempt_start = std::time::Instant::now();
            match self.request_cosign(ledger_id, &update_clone).await {
                Ok(entries) => {
                    let label = format!("success_attempt_{}", attempt);
                    metrics::record_cosign_attempt(&label, attempt_start.elapsed());
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let ledger_arc = ledgers
                        .get(ledger_id)
                        .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
                    let mut ledger = ledger_arc.write().unwrap();

                    // Apply majority cosignatures, recompute current_hash
                    ledger.apply_cosignatures(entries);

                    tracing::debug!(
                        "Applied {} cosigs (new chain_hash: {}...)",
                        ledger
                            .history
                            .last()
                            .map(|u| u.cosignatures.len())
                            .unwrap_or(0),
                        &hex::encode(&ledger.state.chain_tip_hash[..4])
                    );
                    last_error = None;
                    break;
                }
                Err(e) => {
                    let label = format!("timeout_attempt_{}", attempt);
                    metrics::record_cosign_attempt(&label, attempt_start.elapsed());
                    tracing::warn!("Co-sign attempt {}/{} failed: {}", attempt, max_attempts, e);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        // Brief delay before retry — keep short since success latency
                        // is 5-9ms; if the update hasn't arrived by now, a longer wait
                        // just blocks the run loop (which prevents processing OTHER
                        // operators' cosign requests, causing cascading timeouts).
                        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    }
                }
            }
        }

        metrics::record_cosign_duration(cosign_start.elapsed());

        if let Some(e) = last_error {
            if quorum_active {
                // After rotation, co-signatures are required - fail instead of falling back
                metrics::record_sign_and_broadcast("timeout", sab_start.elapsed());
                return Err(Error::Protocol(format!(
                    "Co-signature required after reserves rotation, but all {} attempts failed: {}",
                    max_attempts, e
                )));
            }
            // Before rotation, allow fallback to operator-only
            tracing::warn!(
                "Co-sign multicast failed after {} attempts, using operator-only signature",
                max_attempts
            );
        }

        // Sign as operator
        let t_sign_op = std::time::Instant::now();
        self.sign_last_update(ledger_id)?;
        let sign_op_elapsed = t_sign_op.elapsed();

        // Validate chain consistency before persisting
        let t_validate = std::time::Instant::now();
        self.validate_chain_before_persist(ledger_id)?;
        let validate_elapsed = t_validate.elapsed();

        // Persist the ledger
        let t_persist2 = std::time::Instant::now();
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger after signing: {}", e);
        }
        let persist2_elapsed = t_persist2.elapsed();

        // Broadcast
        let t_broadcast = std::time::Instant::now();
        let result = self.broadcast_last_update(ledger_id).await;
        let broadcast_elapsed = t_broadcast.elapsed();

        tracing::debug!("[PROFILE] sign_and_broadcast inner: cosign_wait=included_above, sign_op={:?}, validate={:?}, persist={:?}, broadcast={:?}",
            sign_op_elapsed, validate_elapsed, persist2_elapsed, broadcast_elapsed);

        metrics::record_sign_and_broadcast("success", sab_start.elapsed());
        result
    }

    /// Add a quorum member with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow:
    /// 1. Appends the QuorumAddMember operation (unsigned)
    /// 2. Requests co-signature from existing quorum member (if any)
    /// 3. Signs as operator
    /// 4. Broadcasts to Nostr
    ///
    /// If there are no existing quorum members, falls back to operator-only signature.
    pub async fn add_quorum_member(
        &self,
        ledger_id: &str,
        quorum_member: PublicKey,
        member_ledger_id: &str,
        signature: [u8; 64],
        min_fee_bps: Option<u16>,
        min_fee_fixed: Option<u64>,
        max_fee_period: Option<u32>,
        membership_until: Option<u32>,
    ) -> Result<String, Error> {
        // Pre-validate
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
            let ledger = ledger_arc.read().unwrap();

            // Check if already a member
            if ledger
                .state
                .quorum_members
                .iter()
                .any(|m| m.pubkey == quorum_member)
            {
                return Err(Error::Protocol("Already a quorum member".to_string()));
            }

            // Check if we've reached the maximum quorum size
            if ledger.state.quorum_members.len() >= MAX_QUORUM_MEMBERS {
                return Err(Error::Protocol(format!(
                    "Maximum quorum size reached ({} members)",
                    MAX_QUORUM_MEMBERS
                )));
            }
        }

        let operation = deposits_core::messages::LedgerOperation::QuorumAddMember {
            quorum_member,
            quorum_member_signature: signature,
            member_ledger_id: member_ledger_id.to_string(),
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            membership_until,
            dispute_response_blocks: None,
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
        };

        self.commit_operation(ledger_id, operation).await
    }

    /// Record a quorum join with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    pub async fn record_quorum_join(
        &self,
        our_ledger_id: &str,
        target_operator: PublicKey,
        target_ledger_id: &str,
        membership_expires: u32,
    ) -> Result<String, Error> {
        // Pre-validate
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(our_ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", our_ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            // Count active (non-expired) quorum memberships from derived state
            let active_quorums = ledger
                .state
                .joined_quorums
                .iter()
                .filter(|jq| jq.membership_expires > block_height)
                .count();

            if active_quorums >= MAX_QUORUMS_JOINED {
                return Err(Error::Protocol(format!(
                    "Maximum active quorums joined reached ({} quorums)",
                    MAX_QUORUMS_JOINED
                )));
            }
        }

        let operation = deposits_core::messages::LedgerOperation::QuorumJoin {
            operator_id: target_operator,
            ledger_id: target_ledger_id.to_string(),
            membership_expires,
        };

        let result = self.commit_operation(our_ledger_id, operation).await;

        // Subscribe to the target ledger's requests so we can receive co-sign requests
        // This is important for quorum members to respond to update co-signing
        if let Err(e) = self.subscribe_to_ledger(target_ledger_id).await {
            tracing::warn!(
                "Failed to subscribe to target ledger {}: {}",
                &target_ledger_id[..16.min(target_ledger_id.len())],
                e
            );
        }

        result
    }

    /// Lock collateral with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    /// Takes a descriptor string (e.g., "pk(02abc...)" for single-key deposits).
    /// Returns the attestation after successfully broadcasting.
    pub async fn lock_collateral(
        &self,
        ledger_id: &str,
        descriptor: &str,
        deposit_secret: &bitcoin::secp256k1::SecretKey,
        amount_msats: u64,
        lock_until_block: u32,
        requesting_operator: PublicKey,
        quorum_member: PublicKey,
    ) -> Result<deposits_core::CollateralAttestationMsg, Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};

        let deposit_id = compute_deposit_id(descriptor);

        // Pre-validate: check deposit exists
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            ledger.state.deposits.get(&deposit_id).ok_or_else(|| {
                Error::Protocol(format!("Deposit not found for descriptor {}", descriptor))
            })?;
        }

        // CollateralLock is now a deprecated no-op; collateral is tracked at the UTXO level.
        // Proceed directly to building the attestation.

        // Build attestation from post-commit state
        let block_height = self.wallet.get_block_height().unwrap_or(0);
        let attestation = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            // Use the requested amount and lock duration for the attestation.
            // Collateral is now tracked at the UTXO level, not per-deposit.
            let locked_amount = amount_msats;
            let lock_expiry = lock_until_block;

            // Get current ledger hash for the attestation
            let ledger_hash = ledger.hash();

            // Get ledger_id (hex-encoded) for the attestation
            let collateral_ledger_id = hex::encode(ledger.state.ledger_id);

            // Create operator's attestation signature
            let mut sign_content = Vec::new();
            sign_content.extend_from_slice(b"COLLATERAL_ATTESTATION:");
            sign_content.extend_from_slice(&requesting_operator.serialize());
            sign_content.extend_from_slice(&quorum_member.serialize());
            sign_content.extend_from_slice(&locked_amount.to_le_bytes());
            sign_content.extend_from_slice(&block_height.to_le_bytes());
            sign_content.extend_from_slice(&lock_expiry.to_le_bytes());
            sign_content.extend_from_slice(&ledger_hash);

            let hash = sha256::Hash::hash(&sign_content);
            let msg = Message::from_digest(hash.to_byte_array());

            let secp = &self.secp;
            let keypair =
                bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);
            let attestation_signature: [u8; 64] = *sig.as_ref();

            deposits_core::CollateralAttestationMsg {
                operator: requesting_operator,
                quorum_member,
                collateral_ledger_id,
                amount: locked_amount,
                block_height,
                lock_until_block: lock_expiry,
                signature: attestation_signature,
                ledger_hash,
            }
        };

        tracing::info!(
            "Created collateral lock for deposit {}: {} msats until block {}, attestation for {}",
            hex::encode(deposit_id),
            attestation.amount,
            attestation.lock_until_block,
            requesting_operator
        );

        Ok(attestation)
    }

    /// Record a collateral attestation with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    pub async fn record_collateral_attestation(
        &self,
        ledger_id: &str,
        attestation: deposits_core::CollateralAttestationMsg,
    ) -> Result<String, Error> {
        // Verify we are the quorum_member in the attestation
        if attestation.quorum_member != self.node_id {
            return Err(Error::Protocol(format!(
                "Attestation is for {}, not us ({})",
                attestation.quorum_member, self.node_id
            )));
        }

        let operation = deposits_core::messages::LedgerOperation::CollateralAttestation {
            collateral_operator: attestation.operator,
            quorum_member: attestation.quorum_member,
            collateral_ledger_id: attestation.collateral_ledger_id.clone(),
            amount: attestation.amount,
            block_height: attestation.block_height,
            lock_until_block: attestation.lock_until_block,
            signature: attestation.signature,
            ledger_hash: attestation.ledger_hash,
        };

        self.commit_operation(ledger_id, operation).await
    }

    /// Open a deposit with co-signing and broadcast.
    ///
    /// Takes a descriptor string (e.g., "pk(02abc...)" for single-key deposits).
    pub async fn open_deposit(
        &self,
        ledger_id: &str,
        descriptor: &str,
        fees: Option<FeeStructure>,
        transfer_fees: Option<deposits_core::TransferFeeSchedule>,
        receive_requires_sig: bool,
    ) -> Result<Deposit, Error> {
        let deposit_id = compute_deposit_id(descriptor);

        // Pre-validate: check deposit doesn't already exist
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = arc.read().unwrap();
            if ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit already exists for descriptor {}",
                    descriptor
                )));
            }
        }

        let operation = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: fees.clone(),
            transfer_fees: transfer_fees.clone(),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };

        self.commit_operation(ledger_id, operation).await?;

        // Read the deposit from the now-committed state
        let deposit = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .cloned()
                .ok_or_else(|| Error::Protocol("Deposit not found after commit".to_string()))?
        };

        tracing::info!(
            "Opened deposit {} in ledger {}",
            hex::encode(deposit_id),
            ledger_id
        );
        Ok(deposit)
    }

    /// Credit a deposit with on-chain funds, with co-signing and broadcast.
    pub async fn credit_deposit_onchain(
        &self,
        ledger_id: &str,
        descriptor: &str,
        amount_msats: u64,
        txid: [u8; 32],
        vout: u32,
        funding_address: String,
    ) -> Result<u64, Error> {
        let deposit_id = compute_deposit_id(descriptor);

        // Pre-validate
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            if !ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for descriptor {}",
                    descriptor
                )));
            }
        }

        let operation = LedgerOperation::OnchainCredit {
            txid,
            vout,
            deposit_id,
            amount: amount_msats,
            funding_address,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        tracing::info!(
            "Credited deposit {} with {} msats (on-chain), new balance: {} msats",
            hex::encode(deposit_id),
            amount_msats,
            new_balance
        );
        Ok(new_balance)
    }

    /// Credit a deposit with Lightning invoice payment, with co-signing and broadcast.
    pub async fn credit_deposit(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
    ) -> Result<u64, Error> {
        let sequence_number = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = arc.read().unwrap();
            if !ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )));
            }
            ledger.sequence() + 1
        };

        let operation = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: amount_msats,
            invoice_id,
            sequence_number,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        tracing::info!(
            "Credited deposit {} with {} msats (invoice), new balance: {} msats",
            hex::encode(deposit_id),
            amount_msats,
            new_balance
        );
        Ok(new_balance)
    }

    /// Lock funds for an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn lock_invoice_payment(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
        witness: DescriptorWitness,
    ) -> Result<u64, Error> {
        // Pre-validate and read sequence number
        let sequence_number = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id).ok_or_else(|| {
                Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                ))
            })?;

            if deposit.available_balance() < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient available balance: {} msats available, {} msats needed",
                    deposit.available_balance(),
                    amount_msats
                )));
            }

            ledger.sequence() + 1
        };

        let operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msats,
            payment_id,
            sequence_number,
            witness,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_locked = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.locked_balance)
                .unwrap_or(0)
        };

        tracing::info!(
            "Locked {} msats for invoice payment {} on deposit {}",
            amount_msats,
            hex::encode(&payment_id[..8]),
            hex::encode(deposit_id)
        );
        Ok(new_locked)
    }

    /// Fail an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn fail_invoice_payment(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
    ) -> Result<u64, Error> {
        // Pre-validate and read sequence number
        let sequence_number = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id).ok_or_else(|| {
                Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                ))
            })?;

            if deposit.locked_balance < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient locked balance: {} msats locked, {} msats to fail",
                    deposit.locked_balance, amount_msats
                )));
            }

            ledger.sequence() + 1
        };

        let operation = LedgerOperation::InvoiceFail {
            deposit_id,
            amount: amount_msats,
            payment_id,
            sequence_number,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        tracing::info!(
            "Failed invoice payment {} for {} msats on deposit {}, new balance: {} msats",
            hex::encode(&payment_id[..8]),
            amount_msats,
            hex::encode(deposit_id),
            new_balance
        );
        Ok(new_balance)
    }

    /// Fulfill an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn fulfill_invoice_payment(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
        witness: DescriptorWitness,
    ) -> Result<u64, Error> {
        // Pre-validate and read sequence number
        let sequence_number = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id).ok_or_else(|| {
                Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                ))
            })?;

            if deposit.locked_balance < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient locked balance: {} msats locked, {} msats to fulfill",
                    deposit.locked_balance, amount_msats
                )));
            }

            ledger.sequence() + 1
        };

        let operation = LedgerOperation::InvoiceFulfill {
            deposit_id,
            amount: amount_msats,
            payment_id,
            preimage,
            sequence_number,
            witness,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        tracing::info!(
            "Fulfilled invoice payment {} for {} msats on deposit {}, new balance: {} msats",
            hex::encode(&payment_id[..8]),
            amount_msats,
            hex::encode(deposit_id),
            new_balance
        );
        Ok(new_balance)
    }

    /// Lock a withdrawal with co-signing and broadcast.
    pub async fn lock_withdrawal(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        destination_address: String,
        amount_sats: u64,
        fee_sats: u64,
        nonce: [u8; 32],
        depositor_witness: DescriptorWitness,
        memo: Option<String>,
    ) -> Result<WithdrawalLockResult, Error> {
        let current_block = self.wallet.get_block_height()?;

        // Compute withdrawal ID
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_id,
            &destination_address,
            amount_sats,
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        // Clone witness for use in OnchainLock operation
        let witness_for_lock = depositor_witness.clone();

        // Create the withdrawal
        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_id,
            destination_address: destination_address.clone(),
            amount_sats,
            fee_sats,
            requested_at_block: current_block,
            memo,
            depositor_witness,
        };

        // Note: Signature verification is skipped here because process_withdraw_request
        // already verified the Schnorr signature. The deposits_core verification expects
        // ECDSA with a different message format, which doesn't match the Nostr request flow.
        // TODO: Unify signature formats between Nostr requests and lock_withdrawal

        // Pre-validate
        let previous_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id).ok_or_else(|| {
                Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                ))
            })?;

            let total_debit_msats = (amount_sats + fee_sats) * 1000;
            if deposit.balance < total_debit_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient balance: {} msats available, {} msats needed",
                    deposit.balance, total_debit_msats
                )));
            }

            deposit.balance
        };

        let operation = LedgerOperation::OnchainLock {
            deposit_id,
            amount: amount_sats * 1000, // Convert to msats
            fee_sats,
            destination_address: destination_address.clone(),
            withdrawal_id,
            witness: witness_for_lock,
        };

        self.commit_operation(ledger_id, operation).await?;

        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Store the withdrawal as locked
        let status = OnChainWithdrawalStatus::Locked {
            locked_at_block: current_block,
        };

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.insert(withdrawal_id, (withdrawal.clone(), status));
        }

        self.save_withdrawals()?;

        let total_debit_msats = withdrawal.total_debit() * 1000;

        tracing::info!(
            "Locked withdrawal {} for {} sats + {} fee to {}, balance {} -> {} msats",
            hex::encode(&withdrawal_id[..8]),
            amount_sats,
            fee_sats,
            withdrawal.destination_address,
            previous_balance,
            new_balance
        );

        Ok(WithdrawalLockResult {
            withdrawal: withdrawal.clone(),
            previous_balance_msats: previous_balance,
            new_balance_msats: new_balance,
            locked_amount_msats: total_debit_msats,
        })
    }

    /// Complete a withdrawal with co-signing and broadcast.
    pub async fn complete_withdrawal(
        &self,
        ledger_id: &str,
        withdrawal_id: &[u8; 32],
    ) -> Result<WithdrawalCompleteResult, Error> {
        let current_block = self.wallet.get_block_height()?;

        // Get the withdrawal
        let withdrawal = {
            let withdrawals = self.withdrawals.lock().unwrap();
            match withdrawals.get(withdrawal_id) {
                Some((w, OnChainWithdrawalStatus::Locked { .. })) => w.clone(),
                Some((_, status)) => {
                    return Err(Error::Protocol(format!(
                        "Withdrawal not in Locked state: {:?}",
                        status
                    )));
                }
                None => return Err(Error::OfferNotFound),
            }
        };

        // Build and broadcast the transaction
        let txid = self.wallet.send_withdrawal(&withdrawal)?;

        // Convert txid string to bytes for the ledger operation
        let txid_bytes: [u8; 32] = hex::decode(&txid)
            .ok()
            .and_then(|v| {
                let mut arr = [0u8; 32];
                if v.len() == 32 {
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);

        let operation = LedgerOperation::OnchainFulfill {
            deposit_id: withdrawal.deposit_id,
            withdrawal_id: *withdrawal_id,
            amount: withdrawal.amount_sats * 1000,
            txid: txid_bytes,
            destination_address: withdrawal.destination_address.clone(),
        };

        self.commit_operation(ledger_id, operation).await?;

        let final_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arc = ledgers.get(ledger_id).unwrap();
            let ledger = arc.read().unwrap();
            ledger
                .state
                .deposits
                .get(&withdrawal.deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Update status
        let new_status = OnChainWithdrawalStatus::Broadcast {
            txid: txid.clone(),
            broadcast_at_block: current_block,
        };

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            if let Some((_, status)) = withdrawals.get_mut(withdrawal_id) {
                *status = new_status;
            }
        }

        self.save_withdrawals()?;

        tracing::info!(
            "Completed withdrawal {}: txid={}, final balance={} msats",
            hex::encode(&withdrawal_id[..8]),
            txid,
            final_balance
        );

        Ok(WithdrawalCompleteResult {
            withdrawal_id: *withdrawal_id,
            txid,
            amount_sats: withdrawal.amount_sats,
            fee_sats: withdrawal.fee_sats,
            final_balance_msats: final_balance,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
        sk.public_key(&secp)
    }

    // ========================================================================
    // build_invoice_signing_data
    // ========================================================================

    #[test]
    fn invoice_signing_data_deterministic() {
        let ledger_id = "aa".repeat(32);
        let payment_hash = [0xbb; 32];
        let deposit_id = [0xcc; 16];
        let amount = 50_000u64;

        let data1 =
            Node::build_invoice_signing_data(&ledger_id, &payment_hash, &deposit_id, amount);
        let data2 =
            Node::build_invoice_signing_data(&ledger_id, &payment_hash, &deposit_id, amount);
        assert_eq!(data1, data2);
    }

    #[test]
    fn invoice_signing_data_format() {
        let ledger_id = "abcd";
        let payment_hash = [0x11; 32];
        let deposit_id = [0x22; 16];
        let amount = 1000u64;

        let data = Node::build_invoice_signing_data(ledger_id, &payment_hash, &deposit_id, amount);

        // Expected: ledger_id bytes + payment_hash + deposit_id + amount_le
        let mut expected = Vec::new();
        expected.extend_from_slice(b"abcd");
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&1000u64.to_le_bytes());

        assert_eq!(data, expected);
        assert_eq!(data.len(), 4 + 32 + 16 + 8); // 60 bytes
    }

    #[test]
    fn invoice_signing_data_different_amounts() {
        let ledger_id = "test";
        let payment_hash = [0x11; 32];
        let deposit_id = [0x22; 16];

        let data_a = Node::build_invoice_signing_data(ledger_id, &payment_hash, &deposit_id, 1000);
        let data_b = Node::build_invoice_signing_data(ledger_id, &payment_hash, &deposit_id, 2000);
        assert_ne!(data_a, data_b);
    }

    #[test]
    fn invoice_signing_data_zero_amount() {
        let data = Node::build_invoice_signing_data("x", &[0; 32], &[0; 16], 0);
        // Last 8 bytes should be zero (LE encoding of 0)
        let len = data.len();
        assert_eq!(&data[len - 8..], &[0u8; 8]);
    }

    // ========================================================================
    // build_offer_signing_data
    // ========================================================================

    #[test]
    fn offer_signing_data_deterministic() {
        let ledger_id = "aa".repeat(32);
        let offer_id = [0xbb; 32];
        let pk = test_pubkey();
        let addr = "bc1qtest";
        let deadline = 850_000u32;

        let data1 = Node::build_offer_signing_data(&ledger_id, &offer_id, &pk, addr, deadline);
        let data2 = Node::build_offer_signing_data(&ledger_id, &offer_id, &pk, addr, deadline);
        assert_eq!(data1, data2);
    }

    #[test]
    fn offer_signing_data_format() {
        let ledger_id = "test";
        let offer_id = [0x11; 32];
        let pk = test_pubkey();
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let deadline = 100u32;

        let data = Node::build_offer_signing_data(ledger_id, &offer_id, &pk, addr, deadline);

        let mut expected = Vec::new();
        // ledger_id bytes
        expected.extend_from_slice(b"test");
        // offer_id (32 bytes)
        expected.extend_from_slice(&[0x11; 32]);
        // operator_id x-coordinate only (skip 02/03 prefix)
        expected.extend_from_slice(&pk.serialize()[1..]);
        // address length (1 byte) + address bytes
        let addr_bytes = addr.as_bytes();
        expected.push(addr_bytes.len() as u8);
        expected.extend_from_slice(addr_bytes);
        // deadline (4 bytes LE)
        expected.extend_from_slice(&100u32.to_le_bytes());

        assert_eq!(data, expected);
    }

    #[test]
    fn offer_signing_data_different_deadlines() {
        let pk = test_pubkey();
        let data_a = Node::build_offer_signing_data("l", &[0; 32], &pk, "addr", 100);
        let data_b = Node::build_offer_signing_data("l", &[0; 32], &pk, "addr", 200);
        assert_ne!(data_a, data_b);
    }

    #[test]
    fn offer_signing_data_different_addresses() {
        let pk = test_pubkey();
        let data_a = Node::build_offer_signing_data("l", &[0; 32], &pk, "bc1q_a", 100);
        let data_b = Node::build_offer_signing_data("l", &[0; 32], &pk, "bc1q_b", 100);
        assert_ne!(data_a, data_b);
    }

    #[test]
    fn offer_signing_data_empty_address() {
        let pk = test_pubkey();
        let data = Node::build_offer_signing_data("l", &[0; 32], &pk, "", 100);
        // Address length byte should be 0
        // Position: 1 (ledger "l") + 32 (offer_id) + 32 (x-only pk) = 65
        assert_eq!(data[65], 0u8);
    }

    #[test]
    fn offer_signing_data_uses_x_only_pubkey() {
        let pk = test_pubkey();
        let data = Node::build_offer_signing_data("l", &[0; 32], &pk, "a", 0);

        // The pubkey portion starts at offset 1 + 32 = 33, and is 32 bytes
        let pk_bytes = &data[33..65];
        // Should be the x-coordinate (skip 02/03 prefix)
        assert_eq!(pk_bytes, &pk.serialize()[1..]);
        // Should NOT include the prefix byte
        assert_ne!(pk_bytes[0], 0x02);
        assert_ne!(pk_bytes[0], 0x03);
    }
}
