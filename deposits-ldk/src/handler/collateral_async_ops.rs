// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Async quorum member operations for the Bitcoin Deposits protocol.

use bitcoin::secp256k1::PublicKey;
use std::str::FromStr;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use deposits_core::messages::CoordinationMsg;
use super::messages::{LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use super::ledger_ext::LedgerExt;
use deposits_core::quorum::LedgerId;
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Add a quorum member to a ledger - async version
    /// Uses async sleep to not block the tokio executor when called from HTTP handlers
    pub async fn add_quorum_member_async(
        &self,
        partner_node_id: PublicKey,
        quorum_member: PublicKey,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Verify ledger exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if !ledgers.contains_key(&(self.our_node_id, partner_node_id.to_string())) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
            // Check the actual ledger state for duplicate quorum member
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.quorum_members.contains(&quorum_member) {
                    log_info!(
                        self.logger,
                        "📋 OPERATOR: Quorum member {} already exists in ledger, skipping",
                        quorum_member
                    );
                    return Err(DepositsError::QuorumMemberAlreadyExists);
                }
            }
        }

        // Also check quorum_manager for redundancy
        {
            let ledger_id = LedgerId::new(self.our_node_id, partner_node_id.to_string());
            if let Some(members) = self.quorum_manager.get_quorum(&ledger_id) {
                if members.contains(&quorum_member) {
                    return Err(DepositsError::QuorumMemberAlreadyExists);
                }
            }
        }

        // Step 1: Request consent from the quorum member (async!)
        log_info!(self.logger, "📨 Requesting consent from quorum member {} to back ledger with partner {}",
            quorum_member, partner_node_id);

        let consent_request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: self.our_node_id,
            reserves_id: partner_node_id.to_string(),
            operator_signature: [0u8; 64],
        });

        // Use async version - doesn't block the executor!
        let quorum_member_signature = self.request_collateral_consent_async(
            quorum_member,
            consent_request,
        ).await?;

        log_info!(self.logger, "✅ Received consent signature from quorum member {}", quorum_member);

        // Step 2: Create the QuorumAddMember message with both signatures (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::QuorumAddMember {
                quorum_member,
                quorum_member_signature,
            },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

        // Track pending ACK
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(message_hash, deposits_core::PendingAck {
                message_type,
                timestamp,
                peer: partner_node_id,
            });
        }

        // Send and wait for ACK (async!)
        match self.send_message_with_ack_async(partner_node_id, message, 30000).await {
            Ok(()) => {
                log_info!(self.logger, "✅ QuorumAddMember ACK received from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get QuorumAddMember ACK from {}: {}", partner_node_id, e);
                return Err(e);
            }
        }

        // Apply the change locally
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                let prev_hash = ledger.tail_hash();
                let new_hash = ledger.append_mut(message_for_broadcast.clone())?;
                let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Update partner_deepest_ack_hash since partner just ACKed this update
                // This is needed BEFORE refresh_reserves_commitment can commit this hash
                ledger.state.partner_deepest_ack_hash = new_hash;

                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_warn!(self.logger, "Failed to persist ledger after adding quorum member: {:?}", e);
                }

                drop(ledger);
                drop(ledgers);

                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
                }

                // Add to quorum BEFORE broadcasting so the new quorum member is included
                // in the broadcast recipients list
                let ledger_id = LedgerId::new(self.our_node_id, partner_node_id.to_string());
                if let Err(e) = self.quorum_manager.add_member(&ledger_id, quorum_member) {
                    log_warn!(
                        self.logger,
                        "Failed to add quorum member {} to quorum: {:?}",
                        quorum_member,
                        e
                    );
                } else {
                    log_info!(
                        self.logger,
                        "✅ Added quorum member {} to quorum for ledger ({}, {})",
                        quorum_member,
                        self.our_node_id,
                        partner_node_id
                    );
                }

                // Retrieve the partner signature that was stored when ACK was received
                let partner_sig = {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    sigs.remove(&message_hash)
                };
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, partner_sig) {
                    log_warn!(self.logger, "Failed to broadcast QuorumAddMember to other partners: {:?}", e);
                }
            }
        }

        // NOTE: We no longer call send_audit_update_to_new_quorum_member here
        // because broadcast_message_to_other_partners already sends to all partners including
        // the new quorum member. Sending both causes duplicate SignedAuditUpdates which
        // triggers sequence mismatch errors at the receiver.
        // The broadcast sends all partners the single new update - for history sync,
        // the new quorum member should request it separately if needed.

        // IMPORTANT: After adding a quorum member, we need to establish collateral
        // attestations from the quorum member's channel. This ensures that when
        // CosignInvoice is validated on the target ledger, received_collateral_amount
        // is properly populated.
        //
        // In the 100%+100% model:
        // - partner_node_id is the target ledger's partner (e.g., charlie for alice→charlie)
        // - quorum_member is the channel partner providing collateral (e.g., bob for alice→bob)
        // - We need to send CollateralIncrease on the quorum_member's channel to get attestations
        //
        // The attestation flow is:
        // 1. Send CollateralIncrease to quorum_member (on alice→bob ledger)
        // 2. quorum_member responds with CollateralAttestation
        // 3. Operator forwards attestation to partner_node_id (on alice→charlie ledger)
        // 4. partner_node_id updates received_collateral_amount
        //
        // This needs to happen proactively so attestations are in place before invoice creation.
        if let Err(e) = self.initialize_collateral_from_quorum_member(quorum_member, partner_node_id).await {
            log_warn!(self.logger, "⚠️ Failed to initialize collateral from quorum member {}: {:?} - attestations may need to be triggered during invoice creation", quorum_member, e);
            // Don't fail - attestations can still be established during invoice creation
        }

        Ok(())
    }

    /// Ensure collateral across ALL operator ledgers for 100%+100% model
    ///
    /// Model: For each channel, OTHER channels must collectively have collateral >= this channel's deposits
    /// Collateral is now an explicit commitment field on each ledger, adjusted via CollateralIncrease/Decrease
    pub(super) async fn ensure_collateral_across_ledgers(&self) -> Result<(), DepositsError> {
        
        use deposits_core::LedgerValidator;
        use super::core::calculate_collateral_with_headroom;

        // STEP 1: Gather deposits and collateral for each ledger
        #[derive(Clone, Debug)]
        struct LedgerInfo {
            partner: String,
            deposits: u64,
            collateral: u64, // Explicit collateral commitment
        }

        let (ledger_infos, adjustments_needed) = {
            let ledgers = self.ledgers.lock().unwrap();

            // Collect info for all operator ledgers
            let mut infos: Vec<LedgerInfo> = Vec::new();
            for ((operator, partner), ledger_arc) in ledgers.iter() {
                if *operator == self.our_node_id {
                    let ledger = ledger_arc.read().unwrap();
                    let deposits = LedgerValidator::total_balance(&ledger);
                    let collateral = ledger.state.collateral_amount;
                    infos.push(LedgerInfo {
                        partner: partner.clone(),
                        deposits,
                        collateral,
                    });
                }
            }

            // For each ledger, check if OTHER ledgers have enough collateral to cover its deposits
            // We need: sum of other ledgers' collateral >= this ledger's deposits + headroom
            let mut adjustments: Vec<(String, u64)> = Vec::new(); // (partner, amount_to_add)

            for ledger in &infos {
                // Sum collateral from OTHER ledgers (what backs THIS ledger's deposits)
                let other_collateral: u64 = infos.iter()
                    .filter(|l| l.partner != ledger.partner)
                    .map(|l| l.collateral)
                    .sum();

                // Required collateral with headroom buffer
                let required_with_headroom = calculate_collateral_with_headroom(ledger.deposits);

                // Only adjust if we're below required (not just below headroom target)
                // This prevents constant adjustments when we're close to the target
                if other_collateral < ledger.deposits {
                    // We're actually undercollateralized - calculate how much we need
                    let shortfall = required_with_headroom.saturating_sub(other_collateral);
                    adjustments.push((ledger.partner.clone(), shortfall));
                }
            }

            (infos, adjustments)
        };

        if adjustments_needed.is_empty() {
            let total_deposits: u64 = ledger_infos.iter().map(|l| l.deposits).sum();
            let total_collateral: u64 = ledger_infos.iter().map(|l| l.collateral).sum();
            log_debug!(self.logger, "✅ COLLATERAL: All ledgers covered. Deposits={}, Collateral={}",
                total_deposits, total_collateral);
            return Ok(());
        }

        // Log the undercollateralized situation
        for (partner, shortfall) in &adjustments_needed {
            log_info!(self.logger, "🔄 COLLATERAL: Ledger {} needs {} sats more collateral from other channels", partner, shortfall);
        }

        // Calculate total shortfall we need to add across other ledgers
        let total_shortfall: u64 = adjustments_needed.iter().map(|(_, s)| *s).sum();

        // Find ledgers we can add collateral to (any ledger that isn't the undercollateralized one)
        // These are ledgers where we'll INCREASE collateral commitment
        let available_ledgers: Vec<String> = ledger_infos.iter()
            .filter(|l| !adjustments_needed.iter().any(|(p, _)| *p == l.partner))
            .map(|l| l.partner.clone())
            .collect();

        if available_ledgers.is_empty() {
            // If all ledgers need more collateral from others, we need to add collateral to ALL of them
            // This happens when total deposits across all channels exceed total collateral
            log_warn!(self.logger, "⚠️ COLLATERAL: All ledgers need more collateral - adding to each");

            // Add collateral evenly to all ledgers
            let per_ledger = total_shortfall.saturating_div(ledger_infos.len() as u64);
            let remainder = total_shortfall % (ledger_infos.len() as u64);

            for (i, info) in ledger_infos.iter().enumerate() {
                let amount = if i == 0 { per_ledger + remainder } else { per_ledger };
                if amount > 0 {
                    let partner_pubkey = PublicKey::from_str(&info.partner)
                        .map_err(|_e| DepositsError::InvalidPublicKey)?;
                    self.increase_collateral_on_ledger(partner_pubkey, amount).await?;
                }
            }
            return Ok(());
        }

        // Distribute shortfall evenly across available ledgers
        let per_ledger_increase = total_shortfall.saturating_div(available_ledgers.len() as u64);
        let remainder = total_shortfall % (available_ledgers.len() as u64);

        log_info!(self.logger, "🔄 COLLATERAL: Need {} sats more collateral, distributing across {} ledger(s)",
            total_shortfall, available_ledgers.len());

        // STEP 2: Increase collateral on each available ledger
        for (i, reserves_id) in available_ledgers.iter().enumerate() {
            // First ledger gets any remainder
            let increase_amount = if i == 0 {
                per_ledger_increase + remainder
            } else {
                per_ledger_increase
            };

            if increase_amount == 0 {
                continue;
            }

            let partner_pubkey = PublicKey::from_str(reserves_id)
                .map_err(|_e| DepositsError::InvalidPublicKey)?;
            self.increase_collateral_on_ledger(partner_pubkey, increase_amount).await?;
        }

        Ok(())
    }

    /// Ensure collateral is in place for an upcoming invoice
    /// This considers the invoice amount as expected future deposits
    pub(super) async fn ensure_collateral_for_invoice(&self, partner_for_invoice: PublicKey, invoice_amount: u64) -> Result<(), DepositsError> {
        use deposits_core::LedgerValidator;
        use super::core::calculate_collateral_with_headroom;

        // STEP 1: Gather deposits and collateral for each operator ledger
        #[derive(Clone, Debug)]
        struct LedgerInfo {
            partner: String,
            deposits: u64,
            collateral: u64,
        }

        let partner_for_invoice_str = partner_for_invoice.to_string();

        let (ledger_infos, shortfall) = {
            let ledgers = self.ledgers.lock().unwrap();

            // Collect info for all operator ledgers
            let mut infos: Vec<LedgerInfo> = Vec::new();
            for ((operator, partner), ledger_arc) in ledgers.iter() {
                if *operator == self.our_node_id {
                    let ledger = ledger_arc.read().unwrap();
                    let current_balance = LedgerValidator::total_balance(&ledger);
                    let mut deposits = current_balance;

                    // Add the invoice amount to expected deposits for this partner's ledger
                    if *partner == partner_for_invoice_str {
                        deposits = deposits.saturating_add(invoice_amount);
                        log_info!(self.logger, "📊 COLLATERAL CHECK: partner={} current_balance={} + invoice={} = expected_deposits={}",
                            partner, current_balance, invoice_amount, deposits);
                    }

                    let collateral = ledger.state.collateral_amount;
                    log_debug!(self.logger, "📊 COLLATERAL CHECK: partner={} collateral_amount={}", partner, collateral);
                    infos.push(LedgerInfo {
                        partner: partner.clone(),
                        deposits,
                        collateral,
                    });
                }
            }

            // Find the ledger that needs collateral backing (the invoice target)
            let target_ledger = infos.iter().find(|l| l.partner == partner_for_invoice_str);
            if target_ledger.is_none() {
                return Err(DepositsError::LedgerNotFound);
            }
            let target_deposits = target_ledger.unwrap().deposits;

            // Sum collateral from OTHER ledgers (what backs the target ledger's deposits)
            let other_collateral: u64 = infos.iter()
                .filter(|l| l.partner != partner_for_invoice_str)
                .map(|l| l.collateral)
                .sum();

            let required = calculate_collateral_with_headroom(target_deposits);
            let shortfall = if other_collateral < target_deposits {
                required.saturating_sub(other_collateral)
            } else {
                0
            };

            log_info!(self.logger, "📊 COLLATERAL CALC: target_deposits={} other_collateral={} required={} shortfall={}",
                target_deposits, other_collateral, required, shortfall);

            (infos, shortfall)
        };

        if shortfall == 0 {
            log_debug!(self.logger, "✅ COLLATERAL: Invoice ledger already covered");
            return Ok(());
        }

        log_info!(self.logger, "🔄 COLLATERAL: Invoice for {} sats needs {} sats more collateral",
            invoice_amount, shortfall);

        // Find ledgers we can add collateral to (any ledger except the invoice target)
        let available_ledgers: Vec<String> = ledger_infos.iter()
            .filter(|l| l.partner != partner_for_invoice_str)
            .map(|l| l.partner.clone())
            .collect();

        if available_ledgers.is_empty() {
            log_error!(self.logger, "❌ COLLATERAL: No other ledgers available to provide collateral");
            return Err(DepositsError::InsufficientCollateral {
                required: shortfall,
                available: 0,
                missing_attestations: vec![],
            });
        }

        // Distribute shortfall evenly across available ledgers
        let per_ledger_increase = shortfall.saturating_div(available_ledgers.len() as u64);
        let remainder = shortfall % (available_ledgers.len() as u64);

        for (i, reserves_id_str) in available_ledgers.iter().enumerate() {
            let increase_amount = if i == 0 {
                per_ledger_increase + remainder
            } else {
                per_ledger_increase
            };
            if increase_amount > 0 {
                let reserves_id = PublicKey::from_str(reserves_id_str)
                    .map_err(|_e| DepositsError::InvalidPublicKey)?;
                // First ensure reserves on the collateral-providing ledger are sufficient
                // Collateral commitment cannot exceed reserves on that ledger
                self.ensure_reserves_for_collateral(reserves_id, increase_amount).await?;
                // Then commit the collateral
                self.increase_collateral_on_ledger(reserves_id, increase_amount).await?;
            }
        }

        Ok(())
    }

    /// Ensure reserves on a ledger are sufficient to support a collateral commitment
    async fn ensure_reserves_for_collateral(&self, reserves_id: PublicKey, collateral_needed: u64) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;
        use super::core::calculate_reserves_with_headroom;

        // Check current reserves and collateral on this ledger
        let (current_reserves, current_collateral) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                (ledger.reserves_amount(), ledger.state.collateral_amount)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        // Reserves must be >= current collateral + new collateral
        let total_collateral_needed = current_collateral.saturating_add(collateral_needed);
        let headroom = calculate_reserves_with_headroom(total_collateral_needed);

        if current_reserves >= headroom {
            log_debug!(self.logger, "✅ RESERVES: Ledger with {} already has sufficient reserves ({}) for collateral ({})",
                reserves_id, current_reserves, total_collateral_needed);
            return Ok(());
        }

        let reserves_increase = headroom.saturating_sub(current_reserves);
        log_info!(self.logger, "🔄 RESERVES: Increasing reserves on ledger with {} by {} sats to support collateral",
            reserves_id, reserves_increase);

        // Send ReservesIncrease message (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            reserves_id.to_string(),          // partner
            LedgerOperation::ReservesIncrease { reserves_id: reserves_id.to_string(), new_amount: headroom },
        );
        let reserves_msg = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&reserves_msg);
        let message_type = reserves_msg.message_type();
        let reserves_msg_for_broadcast = reserves_msg.clone();

        // Track pending ACK before sending
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(message_hash, deposits_core::PendingAck {
                message_type,
                timestamp,
                peer: reserves_id,
            });
        }

        // Send and wait for ACK
        self.send_message_with_ack_async(reserves_id, reserves_msg, 30000).await?;

        // Apply the update locally
        let (prev_hash, new_hash, sequence_number) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                ledger.state.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let (prev, hash, seq) = ledger.append_mut_with_metadata(reserves_msg_for_broadcast.clone())?;

                // Store partner signature from ACK
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                        }
                    }
                }

                ledger.state.partner_deepest_ack_hash = hash;
                self.persist_ledger_state(&*ledger)?;
                (prev, hash, seq)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        // Broadcast to other partners
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, reserves_id.to_string(), reserves_msg_for_broadcast, prev_hash, new_hash, sequence_number));
        }
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, reserves_id, None) {
            log_error!(self.logger, "Failed to broadcast reserves increase: {}", e);
        }

        log_info!(self.logger, "✅ RESERVES: Increased reserves to {} sats on ledger with {}",
            headroom, reserves_id);

        Ok(())
    }

    /// Increase collateral commitment on a specific ledger
    /// Sends CollateralIncrease message and waits for ACK
    /// `increase_by` is the delta amount to add to current collateral
    async fn increase_collateral_on_ledger(&self, reserves_id: PublicKey, increase_by: u64) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Calculate absolute new_amount = current + increase_by
        let new_amount = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                ledger.state.collateral_amount.saturating_add(increase_by)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        log_info!(self.logger, "🔄 COLLATERAL: Increasing collateral to {} sats (adding {}) on ledger with {}",
            new_amount, increase_by, reserves_id);

        // Get current block height
        let block_height = self.channel_manager.as_ref()
            .map(|cm| cm.current_best_block_height())
            .unwrap_or(0);

        // Acquire channel lock for this partner
        let _channel_lock = self.acquire_channel_lock_async(self.our_node_id, reserves_id).await;

        // V2 format
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            reserves_id.to_string(),          // partner
            LedgerOperation::CollateralIncrease { new_amount, block_height },
        );
        let collateral_msg = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&collateral_msg);
        let message_type = collateral_msg.message_type();
        let collateral_msg_for_broadcast = collateral_msg.clone();

        // Track pending ACK before sending
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(message_hash, deposits_core::PendingAck {
                message_type,
                timestamp,
                peer: reserves_id,
            });
        }

        // Send message and wait for ACK
        if let Err(e) = self.send_message_with_ack_async(reserves_id, collateral_msg, 30000).await {
            log_error!(self.logger, "❌ COLLATERAL: Failed to increase collateral with {}: {}", reserves_id, e);
            return Err(e);
        }

        // Apply the update locally after ACK
        let (prev_hash, new_hash, sequence_number, hash_verified) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                ledger.state.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let (prev, hash, seq) = ledger.append_mut_with_metadata(collateral_msg_for_broadcast.clone())?;

                // Store partner signature from ACK
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                            log_debug!(self.logger, "🔏 COLLATERAL: Stored partner signature in ledger entry seq={}", seq);
                        }
                    }
                }

                // Verify our computed hash matches the attestation's ledger_hash
                // This catches ledger divergence before we send UpdateReserves
                let partner_hash = ledger.state.collateral_attestations
                    .get(&reserves_id)
                    .map(|att| att.ledger_hash);

                let hash_verified = match partner_hash {
                    Some(att_hash) if att_hash == hash => {
                        log_info!(self.logger, "✅ COLLATERAL: Hash verified - operator={:02x?} matches partner={:02x?}",
                            &hash[0..8], &att_hash[0..8]);
                        true
                    }
                    Some(att_hash) => {
                        log_error!(self.logger, "❌ COLLATERAL: Hash mismatch! operator={:02x?} partner={:02x?} - ledgers diverged, skipping commitment",
                            &hash[0..8], &att_hash[0..8]);
                        false
                    }
                    None => {
                        log_warn!(self.logger, "⚠️ COLLATERAL: No attestation found for partner {} - cannot verify hash",
                            reserves_id);
                        false
                    }
                };

                ledger.state.partner_deepest_ack_hash = hash;
                self.persist_ledger_state(&*ledger)?;
                (prev, hash, seq, hash_verified)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        // Update for broadcast
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, reserves_id.to_string(), collateral_msg_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
        }

        // Broadcast to other partners (auditors)
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, reserves_id, None) {
            log_error!(self.logger, "Failed to broadcast collateral increase: {}", e);
        }

        log_info!(self.logger, "✅ COLLATERAL: Increased collateral to {} sats on ledger with {}", new_amount, reserves_id);

        // Only refresh commitment if hash was verified
        // This prevents sending UpdateReserves with a hash the partner can't validate
        if hash_verified {
            // Refresh commitment transaction to include the new collateral
            // Cancel any pending lazy sync since we're syncing now
            self.cancel_lazy_sync(reserves_id);
            if let Err(e) = self.refresh_reserves_commitment(reserves_id) {
                log_error!(self.logger, "❌ COLLATERAL: Failed to refresh commitment after increase: {}", e);
                // Don't return error - the collateral increase was successful, commitment will sync later
            }
        } else {
            log_warn!(self.logger, "⚠️ COLLATERAL: Skipping commitment refresh due to hash mismatch - will sync lazily");
        }

        Ok(())
    }

    /// Initialize collateral attestations from a quorum member.
    ///
    /// When a quorum member is added, we need to establish attestations proactively
    /// so they're in place before any invoice is created. This sends a minimal
    /// CollateralIncrease on the quorum member's channel to trigger attestation flow.
    ///
    /// # Arguments
    /// * `quorum_member` - The pubkey of the quorum member (channel partner providing collateral)
    /// * `target_partner` - The pubkey of the target ledger's partner (the one who will receive attestations)
    async fn initialize_collateral_from_quorum_member(
        &self,
        quorum_member: PublicKey,
        target_partner: PublicKey,
    ) -> Result<(), DepositsError> {
        // Check if we have a ledger with this quorum member as partner
        let (has_ledger, current_reserves, current_collateral) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, quorum_member.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                (true, ledger.reserves_amount(), ledger.state.collateral_amount)
            } else {
                (false, 0, 0)
            }
        };

        if !has_ledger {
            log_warn!(
                self.logger,
                "⚠️ No ledger found with quorum member {} as partner - cannot initialize collateral",
                quorum_member
            );
            return Err(DepositsError::LedgerNotFound);
        }

        // Only initialize if we haven't already established collateral on this channel
        if current_collateral > 0 {
            log_info!(
                self.logger,
                "✅ Collateral already established on channel with {} ({}), attestations should flow",
                quorum_member,
                current_collateral
            );
            return Ok(());
        }

        // Use current reserves as the collateral amount (if any), or a minimal amount
        // This triggers the attestation flow without requiring actual deposits yet
        let collateral_to_commit = if current_reserves > 0 {
            current_reserves
        } else {
            // No reserves yet - we'll trigger collateral when reserves are added
            log_info!(
                self.logger,
                "ℹ️ No reserves on channel with {} yet - collateral will be established when reserves are added",
                quorum_member
            );
            return Ok(());
        };

        log_info!(
            self.logger,
            "🔄 Initializing collateral ({}) from quorum member {} for target partner {}",
            collateral_to_commit,
            quorum_member,
            target_partner
        );

        // Send CollateralIncrease to the quorum member's channel
        // This triggers:
        // 1. Quorum member responds with CollateralAttestation
        // 2. We forward attestation to target_partner (and any other partners)
        // 3. Target partner updates their received_collateral_amount
        self.increase_collateral_on_ledger(quorum_member, collateral_to_commit).await?;

        // Wait for attestation forwarding ACKs to complete
        // This ensures target_partner has received and processed the attestation
        // before we return, avoiding race conditions during invoice creation
        {
            use super::messages::consts::LEDGER_UPDATE;
            use tokio::time::{sleep, Duration};

            let start = std::time::Instant::now();
            let timeout = Duration::from_millis(5000);

            loop {
                let pending_ledger_updates = {
                    let pending_acks = self.pending_acks.lock().unwrap();
                    pending_acks.iter()
                        .filter(|(_, ack)| ack.message_type == LEDGER_UPDATE)
                        .count()
                };

                if pending_ledger_updates == 0 {
                    log_debug!(self.logger, "✅ All attestation forwarding ACKs received");
                    break;
                }

                if start.elapsed() > timeout {
                    log_warn!(
                        self.logger,
                        "⚠️ Timeout waiting for {} attestation forwarding ACK(s) - continuing anyway",
                        pending_ledger_updates
                    );
                    break;
                }

                sleep(Duration::from_millis(50)).await;
            }
        }

        log_info!(
            self.logger,
            "✅ Collateral initialized from quorum member {} - attestations should now flow to {}",
            quorum_member,
            target_partner
        );

        Ok(())
    }

    /// Remove reserves output from a channel - async version
    /// Uses async sleep to not block the tokio executor when called from HTTP handlers
    /// Requires: reserves balance is 0 (use reclaim_excess_reserves_async first)
    pub async fn remove_reserves_async(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Validate reserves are 0
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.reserves_amount() > 0 {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "non_zero_reserves".to_string(),
                        details: format!("Cannot remove reserves output with {} sats remaining. Use reclaim_excess_reserves_async first.", ledger.reserves_amount()),
                    });
                }
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        }

        // Send LedgerClose message to close the ledger (which removes reserves output)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::LedgerClose,
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();

        // Track pending ACK
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(message_hash, deposits_core::PendingAck {
                message_type,
                timestamp,
                peer: partner_node_id,
            });
        }

        log_info!(self.logger, "Sending LedgerClose message to partner {}", partner_node_id);

        // Send message and wait for acknowledgment using async version
        self.send_message_with_ack_async(partner_node_id, message.clone(), 30000).await?;

        // After ACK, apply update to ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                ledger.append_mut(message)?;
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // Sync commitment to remove reserves output from channel
        if let Err(e) = self.refresh_reserves_commitment(partner_node_id) {
            log_error!(self.logger, "Failed to sync commitment after reserves removal: {}", e);
            // Don't fail - the ledger update was successful
        }

        log_info!(self.logger, "Successfully removed reserves output from channel with {}", partner_node_id);
        Ok(())
    }

    /// Remove a deposit entirely (when balance is zero) - async version
    /// Uses async sleep to not block the tokio executor when called from HTTP handlers
    pub async fn remove_deposit_async(
        &self,
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // First validate that the deposit exists and has zero balance
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();

                // Ensure deposit balance is zero before removing
                if let Some(deposit) = ledger.state.deposits.get(&deposit_pubkey) {
                    if deposit.balance > 0 {
                        return Err(DepositsError::ProtocolViolation {
                            violation_type: "non_zero_balance".to_string(),
                            details: format!("Cannot remove deposit with non-zero balance: {} msat", deposit.balance),
                        });
                    }
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        }

        // Capture prev_hash before creating message
        let prev_hash = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                ledger.tail_hash()
            } else {
                [0u8; 32]
            }
        };

        // Send DepositClose message to partner (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::DepositClose { pubkey: deposit_pubkey },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_for_broadcast = message.clone();

        log_info!(self.logger, "Sending DepositClose message for deposit {} to partner {}", deposit_pubkey, partner_node_id);

        // Send message and wait for acknowledgment using async version
        self.send_message_with_ack_async(partner_node_id, message.clone(), 30000).await?;

        // After ACK received, apply the update to our ledger and capture new_hash
        let (new_hash, chain_index) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let hash = ledger.append_mut(message_for_broadcast.clone())?;
                let seq = (ledger.history.len() - 1) as u64;
                self.persist_ledger_state(&*ledger)?;
                (hash, seq)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash and broadcast
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
        }

        // Broadcast to other partners (auditors)
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast deposit close: {}", e);
        }

        log_info!(self.logger, "Successfully removed deposit {} from channel with {}", deposit_pubkey, partner_node_id);
        Ok(())
    }
}
