// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Async credit and reserves operations for the Bitcoin Deposits protocol.
//!
//! This module contains async operations for:
//! - Crediting deposits when payments are received
//! - Moving reserves in response to credits
//! - Reclaiming excess reserves

use bitcoin::secp256k1::PublicKey;

use super::core::{calculate_reserves_with_headroom, DepositsHandler};
use deposits_core::DepositsError;
use deposits_core::LedgerManager;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use super::ledger_ext::LedgerExt;
use deposits_core::LedgerValidator;
use deposits_core::{log_error, log_info, PendingAck};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Credit deposit and move 100% of amount to reserves (async with ACK)
    /// The other 100% collateral comes from other channels via ensure_collateral_across_ledgers
    /// This is the standard operation when a Lightning payment is received for a deposit
    pub async fn credit_deposit_and_move_reserves_async(
        &self,
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
        credit_amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
    ) -> Result<(), DepositsError> {
        // Acquire channel lock to prevent commitment signature races
        let _channel_lock = self.acquire_channel_lock_async(self.our_node_id, partner_node_id).await;

        // Calculate amount to move to reserves (100% of credit amount)
        let _reserve_move_amount = credit_amount;

        // STEP 1: Check if we need to send ReservesToReserves topup first
        let new_reserves_amount = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                let future_balance = ledger.state.deposits.values()
                    .map(|d| d.balance)
                    .sum::<u64>() + credit_amount;
                // 100%+100% model: require 100% reserves in this channel
                let required_reserves = future_balance;
                if ledger.reserves_amount() < required_reserves {
                    // Increase to required + headroom to reduce future ReservesToReserves
                    let target = calculate_reserves_with_headroom(required_reserves);
                    Some(target) // Return absolute target amount
                } else {
                    None
                }
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "ledger_not_found".to_string(),
                    details: format!("No ledger found for partner {}", partner_node_id),
                });
            }
        };

        // STEP 2: Send ReservesToReserves if needed and wait for ACK (V2 format)
        let reserves_message_hash_opt = if let Some(new_amount) = new_reserves_amount {
            let update_msg = LedgerUpdateMsg::new_with_operation(
                self.our_node_id,    // operator
                partner_node_id,     // partner
                LedgerOperation::ReservesIncrease { new_amount },
            );
            let reserves_msg = DepositsMessage::LedgerUpdate(update_msg);

            let reserves_message_hash = self.calculate_message_hash(&reserves_msg);
            let message_type = reserves_msg.message_type();
            let reserves_msg_for_broadcast = reserves_msg.clone();

            // Track pending ACK BEFORE sending
            {
                let mut pending_acks = self.pending_acks.lock().unwrap();
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                pending_acks.insert(reserves_message_hash, PendingAck {
                    message_type,
                    timestamp,
                    peer: partner_node_id,
                });
                println!("🔵 ADDED PENDING ACK: hash={:02x?}, type={}", &reserves_message_hash[0..4], message_type);
            }

            // Send and wait for ACK
            self.send_message_with_ack_async(partner_node_id, reserves_msg, 30000).await?;

            // Apply reserves increase - use append_mut_with_metadata to get consistent
            // prev_hash, new_hash, and sequence_number atomically (avoids race condition)
            let (prev_hash, new_hash, sequence_number) = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                    let mut ledger = ledger_arc.write().unwrap();
                    let (prev, hash, seq) = ledger.append_v1_mut_with_metadata(reserves_msg_for_broadcast.clone())?;

                    // CRITICAL: Retrieve partner signature from ACK and store it on the ledger update
                    // This is needed for PORCUPINE validation - without it, partner_signature is [0u8; 64]
                    {
                        let mut sigs = self.received_partner_signatures.lock().unwrap();
                        if let Some(partner_sig) = sigs.remove(&reserves_message_hash) {
                            if let Some(last_update) = ledger.history.last_mut() {
                                last_update.partner_signature = partner_sig;
                                println!("🔏 OPERATOR: Stored partner signature in ledger entry seq={}", seq);
                            }
                        } else {
                            println!("⚠️ OPERATOR: No partner signature found for reserves_message_hash={:02x?}", &reserves_message_hash[0..4]);
                        }
                    }

                    // Update partner_deepest_ack_hash since partner just ACKed this update
                    // This is needed BEFORE refresh_reserves_commitment can commit this hash
                    ledger.state.partner_deepest_ack_hash = hash;

                    self.persist_ledger_state(&*ledger)?;
                    (prev, hash, seq)
                } else {
                    return Err(DepositsError::LedgerNotFound);
                }
            };

            // Update sent_messages_for_broadcast with correct new_hash
            {
                println!("🟣 UPDATE SENT_MESSAGES: hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &reserves_message_hash[0..4], reserves_msg_for_broadcast.message_type(), &prev_hash[0..8], &new_hash[0..8], sequence_number);
                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                sent_messages.insert(reserves_message_hash, (self.our_node_id, partner_node_id, reserves_msg_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
            }

            Some(reserves_message_hash)
        } else {
            None
        };

        // STEP 3: ReceivingCreditPayment with RECORD-THEN-COMMIT pattern
        //
        // This is the ONE operation that needs synchronized commitment:
        // - We are receiving funds, so fraud proof would be against US if commitment is wrong
        // - Other operations either hurt only us, or are enforced by partner's reserves check
        //
        // Flow:
        // 1. Build message and PREDICT the hash (without recording yet)
        // 2. Record to ledger (creates operator signature)
        // 3. Send protocol message to partner and wait for ACK (delivers signature for PORCUPINE)
        // 4. Wait for pending reserves to clear
        // 5. Send UpdateReserves with hash to commitment
        // 6. WAIT for commitment to complete (hash is now committed)
        //
        // Note: PORCUPINE validation requires the operator's signature before accepting commitment.
        // So we must send the signed protocol message BEFORE sending UpdateReserves.

        // Step 3.1: Build message and record to ledger ATOMICALLY
        // CRITICAL: Must hold lock from message creation through recording to prevent race conditions.
        // Previously, releasing the lock between predict and record allowed other operations to
        // modify the ledger, causing hash mismatches.

        let (message, prev_hash, new_hash, chain_index, reserves_amount, voter_set) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();
                let sequence_number = ledger.history.len() as u64;

                // Build V2 LedgerUpdate message with PaymentCredit operation
                let update_msg = LedgerUpdateMsg::new_with_operation(
                    ledger.operator_key(),
                    ledger.partner_key(),
                    LedgerOperation::PaymentCredit {
                        payment_hash,
                        deposit_pubkey,
                        amount: credit_amount,
                        invoice_id: invoice_id.clone(),
                        sequence_number,
                    },
                );
                let msg = DepositsMessage::LedgerUpdate(update_msg);

                // Get voter_set and reserves for commitment (reserves will increase by credit_amount)
                let voter_set = ledger.construct_voter_set();
                let future_reserves = ledger.reserves_amount() + credit_amount;

                // Record to ledger atomically - no gap between building message and recording
                // PORCUPINE requires the operator's signature before accepting commitment.
                // The signature is created when we record to ledger.
                let (prev, hash, seq) = ledger.append_v1_mut_with_metadata(msg.clone())?;

                println!(
                    "📝 ATOMIC RECORD: PaymentCredit hash={:02x?}, prev={:02x?}, seq={}",
                    &hash[0..8], &prev[0..8], seq
                );

                self.persist_ledger_state(&*ledger)?;
                (msg, prev, hash, seq, future_reserves, voter_set)
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "ledger_not_found".to_string(),
                    details: format!("No ledger found for partner {}", partner_node_id),
                });
            }
        };

        let credit_message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone(); // Clone before sending

        // Step 3.2: Track pending ACK and send message to partner (delivers signature to partner)
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(credit_message_hash, PendingAck {
                message_type,
                timestamp,
                peer: partner_node_id,
            });
            println!("🔵 ADDED PENDING ACK: hash={:02x?}, type={}", &credit_message_hash[0..4], message_type);
        }

        // Send message and wait for ACK (this delivers our signature to partner for PORCUPINE)
        self.send_message_with_ack_async(partner_node_id, message, 30000).await?;

        println!(
            "✅ Partner ACKed message, signature delivered. Now committing to channel..."
        );

        // Step 3.4: Wait for any pending reserves to complete
        println!(
            "⏳ RECORD-THEN-COMMIT: Waiting for pending reserves to clear for {}",
            partner_node_id
        );
        self.wait_for_pending_reserves_clear(partner_node_id, 30000).await?;

        // Step 3.5: Send UpdateReserves to commit the hash to the channel
        // Partner now has our signature and can validate via PORCUPINE
        self.commit_specific_hash_to_channel(
            partner_node_id,
            new_hash,
            reserves_amount,
            voter_set,
        )?;

        // Step 3.6: WAIT for commitment to complete
        self.wait_for_commitment_with_hash(
            partner_node_id,
            new_hash,
            30000, // 30 second timeout
        ).await?;

        println!(
            "✅ RECORD-THEN-COMMIT: Commitment verified with hash {:02x?}",
            &new_hash[0..8]
        );

        // Update ledger's channel_deepest_commitment_hash after commitment succeeds
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();
                ledger.state.channel_deepest_commitment_hash = new_hash;
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // Step 3.7: Store partner signature (already received from ACK in step 3.3)
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();

                // Retrieve partner signature from ACK and store it
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&credit_message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                            println!("🔏 OPERATOR: Stored partner signature in ledger entry seq={}", chain_index);
                        }
                    }
                }

                // Update partner_deepest_ack_hash now that partner ACKed
                ledger.state.partner_deepest_ack_hash = new_hash;

                self.persist_ledger_state(&*ledger)?;
            }
        }

        // Update sent_messages_for_broadcast with correct new_hash
        {
            println!("🟣 UPDATE SENT_MESSAGES: hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                &credit_message_hash[0..4], message_for_broadcast.message_type(), &prev_hash[0..8], &new_hash[0..8], chain_index);
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(credit_message_hash, (self.our_node_id, partner_node_id, message_for_broadcast, prev_hash, new_hash, chain_index));
        }

        log_info!(
            self.logger,
            "Credited {} msat to deposit {} (RECORD-THEN-COMMIT complete)",
            credit_amount, deposit_pubkey
        );

        // NOTE: No refresh_reserves_commitment needed here - we already committed via predict-then-commit

        // Broadcast BOTH messages to auditors AFTER all operations complete
        if let Some(reserves_hash) = reserves_message_hash_opt {
            if let Err(e) = self.broadcast_message_to_other_partners(reserves_hash, partner_node_id, None) {
                log_error!(self.logger, "Failed to broadcast reserves topup to auditors: {}", e);
            }
        }
        if let Err(e) = self.broadcast_message_to_other_partners(credit_message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast credit_payment to auditors: {}", e);
        }

        // STEP 4: Top up collateral in OTHER operator ledgers (100%+100% model)
        // After crediting a deposit, ensure all other operator ledgers have reserves >= total deposits
        if let Err(e) = self.ensure_collateral_across_ledgers().await {
            log_error!(self.logger, "Failed to ensure collateral in other ledgers after credit: {}", e);
            // Don't fail the whole operation - the credit succeeded, just log the collateral failure
        }

        Ok(())
    }

    /// Credit deposit and move 100% of amount to reserves (synchronous, auto-commit)
    /// The other 100% collateral comes from other channels via ensure_collateral_across_ledgers
    /// This is a legacy method for testing - production should use credit_deposit_and_move_reserves_async
    pub fn credit_deposit_and_move_reserves(&self, partner_node_id: PublicKey, deposit_pubkey: PublicKey, credit_amount: u64) -> Result<(), DepositsError> {
        // Calculate amount to move to reserves (100% of credit amount)
        let reserve_move_amount = credit_amount;

        // Get next sequence number and clone ledger
        let (sequence_number, cloned_ledger) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                (ledger.history.len() as u64, ledger.clone())
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "ledger_not_found".to_string(),
                    details: format!("No ledger found for partner {}", partner_node_id),
                });
            }
        };

        // Credit deposit with automatic reserves topup using LedgerManager
        let credit_operation = LedgerOperation::PaymentCredit {
            payment_hash: [0u8; 32], // Dummy for testing
            deposit_pubkey,
            amount: credit_amount,
            invoice_id: String::from("test"),
            sequence_number,
        };

        let mut manager = LedgerManager::new(cloned_ledger);
        let _hashes = manager.credit_payment_with_reserves_topup(credit_operation)?;
        let updated_ledger = manager.into_ledger();

        // Store back
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            *ledger_arc.write().unwrap() = updated_ledger;
        }

        // Auto-commit the ledger changes (in NWC/test context, we don't do full commitment coordination)
        // Use current timestamp as pseudo-commitment number
        let commitment_number = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // TODO: Track commitment state in handler

        log_info!(
            self.logger,
            "Credited {} msat to deposit {} and moved {} msat to reserves (auto-committed at {})",
            credit_amount, deposit_pubkey, reserve_move_amount, commitment_number
        );

        Ok(())
    }

    /// Reclaim excess reserves back to channel balance
    /// Sends ReservesToLocal message to move excess reserves back to operator's local balance
    ///
    /// # Arguments
    /// * `partner_node_id` - The partner node in the ledger
    /// * `amount` - Amount to reclaim (0 = reclaim all excess above required)
    pub async fn reclaim_excess_reserves_async(
        &self,
        partner_node_id: PublicKey,
        amount: u64,
    ) -> Result<(), DepositsError> {
        // STEP 1: Calculate how much can be reclaimed
        let (_old_reserves, new_reserves, _reclaim_amount) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();

                // Calculate current required reserves
                let total_deposits = LedgerValidator::total_balance(&ledger);
                let max_outstanding_invoice = ledger.state.deposits.values()
                    .flat_map(|d| d.invoices.iter())
                    .map(|inv| inv.amount)
                    .max()
                    .unwrap_or(0);

                // 100%+100% model: require 100% reserves in this channel
                let required_reserves = total_deposits.saturating_add(max_outstanding_invoice);

                // Keep the headroom when calculating excess (don't reclaim our safety buffer)
                let target_with_headroom = calculate_reserves_with_headroom(required_reserves);
                let old_reserves = ledger.reserves_amount();
                let excess = old_reserves.saturating_sub(target_with_headroom);

                if excess == 0 {
                    return Ok(());
                }

                let reclaim_amount = if amount == 0 {
                    excess  // Reclaim all excess
                } else {
                    amount.min(excess)  // Reclaim specified amount, but not more than excess
                };

                let new_reserves = old_reserves.saturating_sub(reclaim_amount);


                (old_reserves, new_reserves, reclaim_amount)
            } else {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "NoLedger".to_string(),
                    details: format!("No ledger found for partner {}", partner_node_id),
                });
            }
        };

        // STEP 2: Send ReservesToLocal message and wait for ACK
        // Capture prev_hash before creating message
        let prev_hash = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                ledger.tail_hash()
            } else {
                [0u8; 32]
            }
        };

        // V2 format
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id,     // partner
            LedgerOperation::ReservesDecrease { new_amount: new_reserves },
        );
        let reserves_msg = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&reserves_msg);
        let message_type = reserves_msg.message_type();
        let reserves_msg_for_broadcast = reserves_msg.clone();

        // Track pending ACK in ledger BEFORE sending
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let _ledger = ledger_arc.write().unwrap();
                // Track pending ACK
                {
                    let mut pending_acks = self.pending_acks.lock().unwrap();
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    pending_acks.insert(message_hash, PendingAck {
                        message_type,
                        timestamp,
                        peer: partner_node_id,
                    });
                }
                println!("🔵 ADDED PENDING ACK: hash={:02x?}, type={}", &message_hash[0..4], message_type);
            }
        }

        self.send_message_with_ack_async(partner_node_id, reserves_msg, 30000).await?;

        // STEP 3: Apply the same update locally and capture new_hash
        let (new_hash, chain_index) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();

                // Set timestamp
                ledger.state.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Apply reserves decrease and capture new_hash
                let hash = ledger.append_v1_mut(reserves_msg_for_broadcast.clone())?;
                let seq = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Persist the ledger
                self.persist_ledger_state(&*ledger)?;

                (hash, seq)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash and broadcast
        {
            println!("🟣 UPDATE SENT_MESSAGES: hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                &message_hash[0..4], reserves_msg_for_broadcast.message_type(), &prev_hash[0..8], &new_hash[0..8], chain_index);
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, reserves_msg_for_broadcast.clone(), prev_hash, new_hash, chain_index));
        }

        // Now broadcast with correct hashes
        println!("📢 Triggering broadcast after update for hash={:02x?}", &message_hash[0..4]);
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast after update: {}", e);
        }

        Ok(())
    }
}
