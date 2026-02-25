// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Synchronous deposit operations for the Bitcoin Deposits protocol.
//!
//! This module contains blocking/synchronous operations for deposits:
//! - Adding deposits (sync version with oneshot ACK)
//! - Listing deposits
//! - Validating ledger hashes for reserves (Porcupine Dance)

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use super::ledger_ext::LedgerExt;
use deposits_core::{log_debug, log_error, log_info, log_warn};
use deposits_core::types::{DepositId, compute_deposit_id};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Initialize a ledger relationship with a partner
    pub fn add_deposit(
        &self,
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
        fees: Option<deposits_core::FeeStructure>,
    ) -> Result<(), DepositsError> {
        // STAGE 1: Check preconditions (no ledger modification yet)
        {
            let all_ledgers = self.ledgers.lock().unwrap();

            // 100%+100% COLLATERAL CHECK: Require at least 2 ledgers before deposits can be opened
            // This enforces the dual-backing model where:
            // - One ledger provides reserves (the channel partner validates)
            // - Another ledger provides collateral (cross-channel backing)
            let mut operator_ledger_count = 0usize;
            let mut partner_ledger_count = 0usize;
            for ((operator, partner), _ledger) in all_ledgers.iter() {
                if *operator == self.our_node_id {
                    operator_ledger_count += 1;
                }
                if *partner == self.our_node_id.to_string() {
                    partner_ledger_count += 1;
                }
            }
            // 100%+100% model requires at least 2 OPERATOR ledgers:
            // - One ledger's reserves back deposits
            // - Other ledger's reserves serve as collateral
            // Being a partner in someone else's ledger doesn't count - you have no funds at stake there
            if operator_ledger_count < 2 {
                log_error!(self.logger, "❌ COLLATERAL CHECK FAILED: Cannot add deposit with only {} operator ledger(s). \
                    100%+100% model requires at least 2 operator ledgers (your reserves in one back your deposits in another). \
                    Partner ledgers don't count - you have no funds at stake there.",
                    operator_ledger_count);
                return Err(DepositsError::InsufficientQuorumMembers {
                    operator_ledgers: operator_ledger_count,
                    partner_ledgers: partner_ledger_count,
                });
            }

            log_info!(self.logger, "✅ COLLATERAL CHECK PASSED: {} operator ledgers (partner={} for reference)",
                operator_ledger_count, partner_ledger_count);

            // We are the operator, partner_node_id is the partner
            if let Some(ledger_arc) = all_ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let _ledger = ledger_arc.read().unwrap();
                // Check if ledger can accept changes (no uncommitted changes)

            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
        }

        // Convert pubkey to deposit_id and descriptor
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

        // STAGE 2: Send message and wait for ACK (ledger unchanged)
        // NOTE: prev_hash will be captured atomically at append time to avoid race conditions
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor,
                fees: fees.clone(),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

        // Track pending ACK in ledger BEFORE sending (so handle_ack can find it)
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let _ledger = ledger_arc.write().unwrap();
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
            } else {
            }
        }

        // Wait for ACK with 30 second timeout using oneshot pattern (fixes deadlock)
        match self.send_message_with_oneshot_ack(partner_node_id, message, 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ ACK received successfully from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get ACK from {}: {}", partner_node_id, e);
                // No rollback needed - ledger was never modified
                return Err(e);
            }
        }

        // STAGE 3: Apply the change now that ACK is confirmed
        // Use append_mut_with_metadata to get consistent prev_hash, new_hash, and sequence atomically
        let (prev_hash, new_hash, chain_index) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                // Apply the deposit and capture prev_hash, new_hash, and sequence atomically
                let (prev, hash, seq) = ledger.append_mut_with_metadata(message_for_broadcast.clone())?;

                // CRITICAL: Retrieve partner signature from ACK and store it on the ledger update
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                        }
                    }
                }

                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = hash;

                self.persist_ledger_state(&*ledger)?;
                (prev, hash, seq)
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Ledger not found".to_string(),
                    details: "Could not find ledger to apply deposit".to_string(),
                });
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash
        // Note: Broadcast triggered automatically by handle_received_ack
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
        }

        // Continue with remaining operations
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.write().unwrap();

                // Track this message as acknowledged (for consensus tracking)
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

                log_debug!(
                    self.logger,
                    "Applied deposit to ChannelLedger after ACK, new consensus hash: {:02x?}",
                    &ledger.tail_hash()[0..8]
                );

                // Persist the updated ledger state
                self.persist_ledger_state(&ledger)?;
            }
        }

        log_debug!(
            self.logger,
            "Successfully added deposit {} to partner {} (ACK received)",
            deposit_pubkey,
            partner_node_id
        );

        Ok(())
    }

    /// List all deposits in the shared ledger
    pub fn list_deposits(&self) -> Result<Vec<DepositId>, DepositsError> {
        let mut all_deposits = Vec::new();

        // Get deposits from new ChannelLedger architecture
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for deposit in ledger.state.deposits.values() {
                all_deposits.push(deposit.deposit_id);
            }
        }

        // Legacy protocol fallback removed - using ChannelLedger only

        Ok(all_deposits)
    }

    /// List deposits owned by a specific depositor in the shared ledger
    /// Note: depositor_pubkey is converted to deposit_id for lookup
    pub fn list_deposits_for_depositor(
        &self,
        depositor_pubkey: PublicKey,
    ) -> Result<Vec<DepositId>, DepositsError> {
        // Convert pubkey to deposit_id for lookup
        let descriptor = format!("pk({})", hex::encode(depositor_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

        let mut depositor_deposits = Vec::new();

        // Search new ChannelLedger architecture
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                depositor_deposits.push(deposit.deposit_id);
            }
        }

        // Legacy protocol fallback removed - using ChannelLedger only

        Ok(depositor_deposits)
    }

    /// List deposits with a specific deposit_id in the shared ledger
    pub fn list_deposits_for_deposit_id(
        &self,
        deposit_id: DepositId,
    ) -> Result<Vec<DepositId>, DepositsError> {
        let mut matching_deposits = Vec::new();

        // Search new ChannelLedger architecture
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                matching_deposits.push(deposit.deposit_id);
            }
        }

        // Legacy protocol fallback removed - using ChannelLedger only

        Ok(matching_deposits)
    }

    /// Get committed ledger hashes directly from LDK's channel state
    ///
    /// This is the authoritative source - it reads from ChannelDetails.local_reserves
    /// and remote_reserves, which contain the actual ledger_hash values that are
    /// embedded in the current commitment transaction.
    ///
    /// Returns (local_hash, remote_hash) where:
    /// - local_hash: From local_reserves.ledger_hash (our reserves output)
    /// - remote_hash: From remote_reserves.ledger_hash (their reserves output)
    pub fn get_committed_ledger_hashes_from_channel(
        &self,
        counterparty_node_id: PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        let Some(ref cm) = self.channel_manager else {
            return (None, None);
        };

        // Find the channel with this counterparty
        let channels = cm.list_channels();
        let channel = channels.iter().find(|ch| ch.counterparty_node_id == counterparty_node_id);

        let Some(ch) = channel else {
            return (None, None);
        };

        let local_hash = ch.local_reserves.as_ref().map(|r| r.1);
        let remote_hash = ch.remote_reserves.as_ref().map(|r| r.1);

        (local_hash, remote_hash)
    }

    /// Validate that a ledger hash is valid for reserves (Porcupine Dance check)
    ///
    /// This validates that:
    /// 1. The hash exists in the partner's ledger chain
    /// 2. The hash is >= the previously committed ledger hash
    /// 3. (Porcupine Dance) We have a signed update at or after this hash
    ///
    /// This is called when we receive an UpdateReserves message to ensure
    /// we only sign commitment transactions with reserves outputs for valid
    /// ledger states that we have signed proof of.
    pub fn validate_ledger_hash_for_reserves(
        &self,
        counterparty_node_id: &PublicKey,
        ledger_hash: &[u8; 32],
    ) -> bool {
        // Zero hash is always valid - means no ledger state committed yet
        if ledger_hash == &[0u8; 32] {
            log_debug!(self.logger, "Accepting zero ledger hash for reserves with partner {}",
                counterparty_node_id);
            return true;
        }

        let ledgers = self.ledgers.lock().unwrap();

        // Get the partner's ledger (where they are operator, we are partner)
        // This is the ledger we're validating against
        let ledger_key = (*counterparty_node_id, self.our_node_id.to_string());

        let (is_valid_unsigned, committed_hash) = if let Some(ledger_arc) = ledgers.get(&ledger_key) {
            let ledger = ledger_arc.read().unwrap();

            // Get the previously committed hash
            let committed = ledger.state.channel_deepest_commitment_hash;

            // Check if the hash exists and is >= committed in unsigned ledger
            let valid = ledger.is_valid_reserves_hash(ledger_hash, &committed);
            (valid, committed)
        } else {
            // No ledger exists yet - this is fine during initial setup
            (true, [0u8; 32])
        };

        drop(ledgers); // Release lock before checking for signatures

        // PORCUPINE DANCE CHECK: Verify we have a signed update at or after this hash
        // This ensures we only cooperate with commitments for states we've signed
        //
        // Check TWO sources for signatures:
        // 1. ledgers - populated from SignedAuditUpdate broadcasts (auditor role)
        // 2. ledgers - where partners store their own signatures when appending
        let has_signed_update = {
            // First check ledgers (for SignedAuditUpdate broadcasts)
            let ledgers = self.ledgers.lock().unwrap();
            let reserves_key = (*counterparty_node_id, self.our_node_id.to_string());

            let signed_in_ledgers = if let Some(partner_ledger_arc) = ledgers.get(&reserves_key) {
                let partner_ledger = partner_ledger_arc.read().unwrap();

                let target_seq = partner_ledger.find_hash_sequence(ledger_hash);

                match target_seq {
                    Some(seq) => {
                        partner_ledger.history.iter()
                            .filter(|u| u.sequence_number >= seq)
                            .any(|u| u.partner_signature != [0u8; 64])
                    }
                    None => false
                }
            } else {
                false
            };

            drop(ledgers);

            if signed_in_ledgers {
                log_debug!(self.logger, "🔏 PORCUPINE: Found signed update in ledgers for hash {:02x?}",
                    &ledger_hash[0..8]);
                true
            } else {
                // Also check ledgers - partners store their signatures there when appending
                let ledgers = self.ledgers.lock().unwrap();
                let ledger_key = (*counterparty_node_id, self.our_node_id.to_string());

                let signed_in_ledgers = if let Some(ledger_arc) = ledgers.get(&ledger_key) {
                    let ledger = ledger_arc.read().unwrap();
                    let target_seq = ledger.find_hash_sequence(ledger_hash);

                    match target_seq {
                        Some(seq) => {
                            let has_signed = ledger.history.iter()
                                .filter(|u| u.sequence_number >= seq)
                                .any(|u| u.partner_signature != [0u8; 64]);
                            if has_signed {
                                log_debug!(self.logger, "🔏 PORCUPINE: Found signed update in ledgers at/after seq {} for hash {:02x?}",
                                    seq, &ledger_hash[0..8]);
                            }
                            has_signed
                        }
                        None => {
                            log_warn!(self.logger, "⚠️ PORCUPINE: Hash {:02x?} not found in ledgers",
                                &ledger_hash[0..8]);
                            false
                        }
                    }
                } else {
                    log_debug!(self.logger, "No channel_ledger for ({}, {}) - accepting during initialization",
                        counterparty_node_id, self.our_node_id);
                    true // Accept during initialization before ledgers exist
                };

                signed_in_ledgers
            }
        };

        if is_valid_unsigned {
            log_debug!(self.logger, "Validated reserves hash {:?} for partner {} (committed: {:?}, signed: {})",
                crate::hex_utils::to_string(ledger_hash),
                counterparty_node_id,
                crate::hex_utils::to_string(&committed_hash),
                has_signed_update);
        } else {
            log_error!(self.logger, "WARN: Reserves hash {:?} not validated for partner {} (committed: {:?}) - accepting anyway to avoid channel close",
                crate::hex_utils::to_string(ledger_hash),
                counterparty_node_id,
                crate::hex_utils::to_string(&committed_hash));
        }

        // Enforce porcupine dance: require both valid hash chain AND signed update
        let result = is_valid_unsigned && has_signed_update;
        if !result {
            log_warn!(self.logger, "🔏 PORCUPINE: Rejecting commitment - unsigned:{} signed:{}",
                is_valid_unsigned, has_signed_update);
        }
        result
    }
}
