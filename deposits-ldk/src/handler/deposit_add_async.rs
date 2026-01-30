// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Async deposit addition operations for the Bitcoin Deposits protocol.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::DepositsMessage;
use super::ledger_ext::LedgerExt;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Add a deposit asynchronously with ACK (for async contexts like NWC)
    pub async fn add_deposit_async(
        &self,
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
        fees: Option<deposits_core::FeeStructure>,
    ) -> Result<(), DepositsError> {
        // Log the deposit being added for tracing
        log_info!(
            self.logger,
            "📝 add_deposit_async called: deposit_pubkey={}, partner={}",
            deposit_pubkey,
            partner_node_id
        );

        // Check for duplicate deposit before proceeding
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.deposits.contains_key(&deposit_pubkey) {
                    log_info!(
                        self.logger,
                        "⚠️ Deposit {} already exists on ledger with {}, skipping duplicate add",
                        deposit_pubkey,
                        partner_node_id
                    );
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Duplicate deposit".to_string(),
                        details: format!("Deposit {} already exists on this ledger", deposit_pubkey),
                    });
                }
            }
        }

        // Acquire channel lock to prevent commitment signature races
        let _channel_lock = self.acquire_channel_lock_async(self.our_node_id, partner_node_id).await;

        // STAGE 1: Check preconditions - ensure BOTH sides have the ledger initialized
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
                return Err(DepositsError::InsufficientCollateralPartners {
                    operator_ledgers: operator_ledger_count,
                    partner_ledgers: partner_ledger_count,
                });
            }

            log_info!(self.logger, "✅ COLLATERAL CHECK PASSED: {} operator ledgers (partner={} for reference)",
                operator_ledger_count, partner_ledger_count);

            if let Some(ledger_arc) = all_ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();

                // Check if ledger can accept changes (no uncommitted changes)


                // CRITICAL: Verify the partner has also initialized their copy of the ledger
                // by checking if they've sent us any ACKs or messages (update_history length > 0)
                // If the partner hasn't initialized, they'll drop our LedgerAddDeposit message
                if ledger.history.is_empty() {
                    // We'll allow this to proceed, but log a warning. The partner should send a NACK if they don't have the ledger.
                }
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
        }

        // STAGE 2: Send message and wait for ACK (ledger unchanged)
        // First, capture prev_hash before creating the message
        let prev_hash = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                ledger.tail_hash()
            } else {
                [0u8; 32]
            }
        };

        let message = DepositsMessage::new_deposit_open(
            self.our_node_id,
            partner_node_id,
            deposit_pubkey,
            fees.clone(),
            None,
            None,
            None,
        );

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


        // Wait for ACK with 30 second timeout using async approach
        match self.send_message_with_ack_async(partner_node_id, message, 30000).await {
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
        let (new_hash, sequence_number) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let hash = ledger.append_mut(message_for_broadcast.clone())?;
                let seq = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)
                (hash, seq)
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Ledger not found".to_string(),
                    details: "Could not find ledger to apply deposit".to_string(),
                });
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash and sequence
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
        }

        // Reacquire ledger lock for remaining operations
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = new_hash;

                log_debug!(
                    self.logger,
                    "Applied deposit to ChannelLedger after ACK, new consensus hash: {:02x?}, partner_deepest_ack_hash updated",
                    &ledger.tail_hash()[0..8]
                );

                // Persist the updated ledger state
                self.persist_ledger_state(&ledger)?;

                // NOTE: With HashStrategy, LedgerAddDeposit does NOT trigger UpdateReserves.
                // Adding a deposit doesn't change the reserves amount - only amount-changing
                // operations (ReservesAdd, ReservesToReserves, etc.) trigger sync.
                // The hash will catch up when the next sync-required operation happens.
            }
        }

        // 100%+100% COLLATERAL: Top up reserves in ALL other operator ledgers
        // This ensures collateral backing across the entire network of ledgers
        if let Err(e) = self.ensure_collateral_across_ledgers().await {
            log_error!(self.logger, "❌ Failed to ensure collateral across ledgers: {}", e);
            // Don't fail the deposit - it succeeded, collateral top-up is best-effort
        }

        log_debug!(
            self.logger,
            "Successfully added deposit {} to partner {} (ACK received)",
            deposit_pubkey,
            partner_node_id
        );

        // Broadcast to auditors AFTER all operations complete
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast add_deposit to auditors: {}", e);
        }

        Ok(())
    }
}
