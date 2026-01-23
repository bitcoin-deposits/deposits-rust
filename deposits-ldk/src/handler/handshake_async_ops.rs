// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Async handshake and invoice operations for the Bitcoin Deposits protocol.
//!
//! This module contains async operations for:
//! - Requesting invoice cosignatures from partners
//! - Initiating ledger handshakes
//! - Peer protocol support checking

use bitcoin::secp256k1::PublicKey;
use tokio::sync::oneshot;

use super::core::{build_taproot_reserves_script, DepositsHandler};
use deposits_core::DepositsError;
use super::messages::{LedgerUpdateMsg, LedgerOperation};
use super::ledger_ext::{LedgerExt, SignedLedgerUpdateExt};
use deposits_core::VoterSet;
use deposits_core::Invoice;
use deposits_core::LedgerValidator;
use lightning::ln::chan_utils::CommitmentExtraOutput;
use lightning::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

/// Helper to calculate reserves with headroom
fn calculate_reserves_with_headroom(required: u64) -> u64 {
    // Add 20% headroom to reduce future ReservesToReserves operations
    required.saturating_add(required / 5)
}

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Request invoice cosignature from partner (async)
    /// Returns the cosignature from the partner
    pub async fn request_invoice_cosignature(
        &self,
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
        payment_hash: [u8; 32],
        amount: u64,
        bolt11: String,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, DepositsError> {
        use super::messages::DepositsMessage;
        use crate::wire::types::PendingInvoice;
        use tokio::time::{sleep, Duration};

        // Acquire channel lock to prevent commitment signature races
        let _channel_lock = self.acquire_channel_lock_async(self.our_node_id, partner_node_id).await;

        // STEP 1: Calculate required reserves and send ReservesToReserves if needed
        let reserves_increase_amount = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();

                // Calculate current state
                let total_deposits = LedgerValidator::total_balance(&ledger);
                let current_max_invoice = ledger.state.deposits.values()
                    .flat_map(|d| d.invoices.iter())
                    .map(|inv| inv.amount)
                    .max()
                    .unwrap_or(0);

                // Calculate what max will be with this new invoice
                let new_max_invoice = std::cmp::max(current_max_invoice, amount);

                // Calculate required reserves (100% + max invoice)
                // The other 100% collateral comes from other channels
                let required_reserves = total_deposits.saturating_add(new_max_invoice);

                // Check if we need to increase reserves
                let current_reserves = ledger.reserves_amount();
                if current_reserves < required_reserves {
                    // Increase to required + headroom to reduce future ReservesToReserves
                    let target = calculate_reserves_with_headroom(required_reserves);
                    Some(target) // Return absolute target amount
                } else {
                    None
                }
            } else {
                None
            }
        };

        // STEP 2: Send ReservesToReserves message if needed and wait for ACK
        if let Some(new_reserves_amount) = reserves_increase_amount {
            use super::messages::DepositsMessage;

            // V2 format
            let update_msg = LedgerUpdateMsg::new_with_operation(
                self.our_node_id,    // operator
                partner_node_id,     // partner
                LedgerOperation::ReservesIncrease { new_amount: new_reserves_amount },
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
                    pending_acks.insert(message_hash, (message_type, timestamp));
                }
                    println!("🔵 ADDED PENDING ACK: hash={:02x?}, type={}", &message_hash[0..4], message_type);
                }
            }

            // Send message and wait for ACK
            self.send_message_with_ack_async(partner_node_id, reserves_msg, 30000).await?;

            // Now apply the same update locally - use append_mut_with_metadata to get
            // consistent prev_hash, new_hash, and sequence_number atomically
            let (prev_hash, new_hash, sequence_number) = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                    let mut ledger = ledger_arc.write().unwrap();

                    // Set timestamp
                    ledger.state.last_updated = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Apply reserves increase and get all metadata atomically
                    let (prev, hash, seq) = ledger.append_v1_mut_with_metadata(reserves_msg_for_broadcast.clone())?;

                    // CRITICAL: Retrieve partner signature from ACK and store it on the ledger update
                    {
                        let mut sigs = self.received_partner_signatures.lock().unwrap();
                        if let Some(partner_sig) = sigs.remove(&message_hash) {
                            if let Some(last_update) = ledger.history.last_mut() {
                                last_update.partner_signature = partner_sig;
                                println!("🔏 OPERATOR: Stored partner signature in ledger entry seq={}", seq);
                            }
                        }
                    }

                    // Update partner_deepest_ack_hash since partner just ACKed this update
                    ledger.state.partner_deepest_ack_hash = hash;

                    // Persist the ledger
                    self.persist_ledger_state(&*ledger)?;

                    (prev, hash, seq)
                } else {
                    return Err(DepositsError::LedgerNotFound);
                }
            };

            // Update sent_messages_for_broadcast with correct new_hash and broadcast
            {
                println!("🟣 UPDATE SENT_MESSAGES: hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &message_hash[0..4], reserves_msg_for_broadcast.message_type(), &prev_hash[0..8], &new_hash[0..8], sequence_number);
                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, reserves_msg_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
            }

            // Now broadcast with correct hashes
            println!("📢 Triggering broadcast after update for hash={:02x?}", &message_hash[0..4]);
            if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
                log_error!(self.logger, "Failed to broadcast after update: {}", e);
            }
        }

        // STEP 2b: Ensure collateral for this invoice (100%+100% model)
        // When making an invoice, we need collateral to be committed on OTHER ledgers
        // to back potential credits on THIS ledger. This must happen BEFORE
        // the invoice can be paid, not after the credit is received.
        // We pass the invoice amount so collateral is calculated for expected deposits.
        if let Err(e) = self.ensure_collateral_for_invoice(partner_node_id, amount).await {
            log_error!(self.logger, "❌ Failed to ensure collateral for invoice: {}", e);
            // For now, log but don't fail - we'll add strict enforcement later
        }

        // Wait for pending CollateralStatus ACKs to complete
        // The CollateralAttestation triggers sending of CollateralStatus to channel partners.
        // We must wait for those ACKs before sending the cosign request, otherwise the
        // partner will see 0 collateral.
        //
        // Note: The oneshot notification is now deferred in message_dispatch.rs until AFTER
        // handle_collateral_attestation completes, so CollateralStatus is already in
        // pending_acks when we reach this point. No initial delay needed.
        {
            use super::messages::consts::COLLATERAL_STATUS;

            let start = std::time::Instant::now();
            let timeout = Duration::from_millis(5000);

            loop {
                let pending_collateral_status = {
                    let pending_acks = self.pending_acks.lock().unwrap();
                    pending_acks.iter()
                        .filter(|(_, (msg_type, _))| *msg_type == COLLATERAL_STATUS)
                        .count()
                };

                if pending_collateral_status == 0 {
                    log_debug!(self.logger, "✅ All CollateralStatus ACKs received");
                    break;
                }

                if start.elapsed() > timeout {
                    log_warn!(self.logger, "⚠️ Timeout waiting for {} CollateralStatus ACK(s)", pending_collateral_status);
                    break;
                }

                sleep(Duration::from_millis(50)).await;
            }
        }

        // STEP 3: Create PendingInvoice
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour expiry

        let invoice_id = hex::encode(&payment_hash);

        // Keep a copy of invoice data for adding to ledger after cosign succeeds
        let invoice_for_ledger = Invoice {
            id: invoice_id.clone(),
            payment_hash,
            amount,
            expires,
            assigned_deposit: deposit_pubkey,
            bolt11: bolt11.clone(),
        };

        let pending_invoice = PendingInvoice::new(
            amount,
            payment_hash,
            expires,
            deposit_pubkey,
            invoice_id,
            bolt11,
        );

        // STEP 3: Create ReceivingCosignInvoice message
        let message = DepositsMessage::ReceivingCosignInvoice {
            pending_invoice,
        };

        // Calculate message hash for tracking
        let message_hash = self.calculate_message_hash(&message);

        // Create oneshot channel for receiving cosignature
        let (tx, rx) = oneshot::channel();

        // Register pending cosignature request
        {
            let mut pending_cosignature_requests = self.pending_cosignature_requests.lock().unwrap();
            pending_cosignature_requests.insert(message_hash, tx);
            println!("🔐 OPERATOR: Registered pending cosignature request for hash {:02x?}, total pending: {}",
                     &message_hash[0..4], pending_cosignature_requests.len());
        }

        // NOTE: ReceivingCosignInvoice is a coordination message, NOT a ledger update
        // It doesn't modify state, so we don't add pending ACK or track it in the ledger chain

        // Send the message
        println!("📤 OPERATOR: Sending ReceivingCosignInvoice message (type {}) to {}",
                 message.message_type(), partner_node_id);
        self.send_message(partner_node_id, message.clone())?;

        // Brief yield to let background processor deliver the message
        sleep(Duration::from_millis(1)).await;

        // Wait for cosignature with proper async await and timeout (no polling!)
        let timeout_duration = Duration::from_millis(timeout_ms);

        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(Ok(signature))) => {
                // Cosignature received successfully - add invoice to deposit in ledger
                {
                    let ledgers = self.ledgers.lock().unwrap();
                    if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                        let mut ledger = ledger_arc.write().unwrap();
                        if let Some(deposit) = ledger.state.deposits.get_mut(&deposit_pubkey) {
                            // Convert wrapper to core type for storage
                            deposit.invoices.push(invoice_for_ledger.into());
                            log_info!(self.logger, "📋 Added invoice to deposit {} (payment_hash: {:02x?})",
                                     deposit_pubkey, &payment_hash[0..4]);
                        }
                    }
                }
                return Ok(signature);
            }
            Ok(Ok(Err(error_msg))) => {
                // Partner rejected the cosigning request
                self.pending_cosignature_requests.lock().unwrap().remove(&message_hash);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Cosigning rejected".to_string(),
                    details: error_msg,
                });
            }
            Ok(Err(_)) => {
                // Channel closed before receiving response
                self.pending_cosignature_requests.lock().unwrap().remove(&message_hash);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Cosignature channel closed".to_string(),
                    details: "Channel was closed before receiving cosignature".to_string(),
                });
            }
            Err(_) => {
                // Timeout
                self.pending_cosignature_requests.lock().unwrap().remove(&message_hash);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Cosignature timeout".to_string(),
                    details: format!("No cosignature received from {} within {}ms", partner_node_id, timeout_ms),
                });
            }
        }
    }

    /// Initiate ledger creation handshake with a partner (async)
    pub async fn initiate_ledger_handshake_async(
        &self,
        partner_node_id: PublicKey,
        ledger_address: bitcoin::Address,
    ) -> Result<(), DepositsError> {
        use super::messages::{DepositsMessage, LedgerOpenRequestMsg};

        // Check if ledger already exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if ledgers.contains_key(&(self.our_node_id, partner_node_id)) {
                return Ok(());
            }
        }

        // Get funding outpoint for the channel with this partner
        let (funding_txid, funding_vout) = if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&partner_node_id);
            if let Some(channel) = channels.first() {
                if let Some((txid, vout)) = &channel.funding_txo {
                    let txid_slice: &[u8] = txid.as_ref();
                    let txid_arr: [u8; 32] = txid_slice.try_into().expect("Txid is always 32 bytes");
                    (txid_arr, *vout as u16)
                } else {
                    ([0u8; 32], 0u16)
                }
            } else {
                ([0u8; 32], 0u16)
            }
        } else {
            ([0u8; 32], 0u16)
        };

        // Send LedgerOpenRequest with the ledger address and funding outpoint
        let init_msg = DepositsMessage::LedgerOpenRequest(LedgerOpenRequestMsg {
            protocol_version: 1,
            min_protocol_version: 1,
            features: 0,
            public_key: self.our_node_id,
            partner_id: partner_node_id,
            ledger_address: ledger_address.to_string(),
            funding_txid,
            funding_vout,
        });

        let message_hash = self.calculate_message_hash(&init_msg);
        let message_type = init_msg.message_type();

        // Track pending ACK BEFORE sending (even though ledger doesn't exist yet)
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pending_acks.insert(message_hash, (message_type, timestamp));
            println!("🔵 ADDED PENDING ACK: hash={:02x?}, type={}", &message_hash[0..4], message_type);
        }

        // Wait for LedgerOpenRequestResponse with ACK
        match self.send_message_with_ack_async(partner_node_id, init_msg, 30000).await {
            Ok(()) => {
            }
            Err(e) => {
                return Err(e);
            }
        }

        // Now both sides should create the ledger

        // Save ledger address string before moving the address
        let ledger_addr_str = ledger_address.to_string();

        self.initialize_ledger(partner_node_id, ledger_address)?;

        // Broadcast LedgerOpenRequest to all other partners (auditors)
        // This is the first update (seq=0 in ledger, seq=1 in SignedAuditUpdate)
        {
            // Get the LedgerOpenRequest message from the ledger (first update)
            let (handshake_msg_opt, new_hash) = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                    let ledger = ledger_arc.read().unwrap();
                    // Get the first update and deserialize its message using SignedLedgerUpdateExt
                    // which correctly uses the separate message_type field
                    let msg_opt = ledger.history.first()
                        .and_then(|update| update.get_message().ok());
                    (msg_opt, ledger.tail_hash())
                } else {
                    (None, [0u8; 32])
                }
            };

            if let Some(handshake_msg) = handshake_msg_opt {
                let prev_hash = [0u8; 32]; // LedgerOpenRequest is the first update
                let chain_index = 0u64; // First update in the chain (0-based, index 0)

                // Store in sent_messages_for_broadcast for SignedAuditUpdate broadcast
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, handshake_msg, prev_hash, new_hash, chain_index));
                }

                println!("🟢 TRIGGERING broadcast after LedgerOpenRequest append");
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
                    log_warn!(self.logger, "Failed to broadcast LedgerOpenRequest to other partners: {:?}", e);
                }
            }
        }

        // Create reserves outputs on the channel's commitment transaction
        // Initial reserves start at 330 sats (dust limit minimum) with zero ledger hash
        // These will be updated to actual reserves_amount once deposits are made
        if let Some(ref cm) = self.channel_manager {
            // Find the channel with this partner
            let channels = cm.list_channels_with_counterparty(&partner_node_id);
            if let Some(channel) = channels.first() {
                // Initial reserves: minimum dust limit (330 sats), will be updated via refresh_reserves_commitment
                // when deposits are made and reserves_amount increases
                let initial_reserves_sats = 330;
                let zero_hash = [0u8; 32];

                // Get VoterSet from the newly created ledger
                let voter_set = {
                    let ledgers = self.ledgers.lock().unwrap();
                    let operator_key = (self.our_node_id, partner_node_id);
                    if let Some(ledger_arc) = ledgers.get(&operator_key) {
                        ledger_arc.read().unwrap().construct_voter_set()
                    } else {
                        // Fallback: simple VoterSet with partner as tie-breaker, no other voters
                        VoterSet::new(partner_node_id, vec![])
                    }
                };

                // Build Taproot reserves script (P2TR) with zero ledger hash for initial setup
                let script_pubkey = match build_taproot_reserves_script(
                    voter_set,
                    zero_hash,
                    self.network,
                ) {
                    Ok(script) => script,
                    Err(e) => {
                        log_error!(
                            self.logger,
                            "Failed to build Taproot reserves script with {}: {:?}",
                            partner_node_id,
                            e
                        );
                        return Ok(());
                    }
                };

                // Use the generic extra outputs API directly
                let script_pubkey_clone = script_pubkey.clone();
                let output = CommitmentExtraOutput {
                    amount_satoshis: initial_reserves_sats,
                    script_pubkey,
                };
                match cm.propose_extra_outputs(
                    &partner_node_id,
                    &channel.channel_id,
                    vec![output],
                ) {
                    Ok(_) => {
                        // Track pending commitment
                        {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let mut pending = self.pending_reserves_commitments.lock().unwrap();
                            pending.insert(partner_node_id, (script_pubkey_clone, zero_hash, initial_reserves_sats, now));
                        }
                        log_info!(
                            self.logger,
                            "Created initial reserves outputs ({} sats) on channel {} with {}",
                            initial_reserves_sats,
                            hex::encode(channel.channel_id.0),
                            partner_node_id
                        );
                    },
                    Err(e) => {
                        log_error!(
                            self.logger,
                            "Failed to create reserves outputs on channel with {}: {:?}",
                            partner_node_id,
                            e
                        );
                    }
                }
            } else {
                log_error!(
                    self.logger,
                    "No channel found with partner {} during handshake completion",
                    partner_node_id
                );
            }
        }

        // Broadcast the LedgerOpenRequest to all other partners as signed audit update
        // IMPORTANT: Use same funding info as the original message for consistent hash
        let init_msg_for_broadcast = DepositsMessage::LedgerOpenRequest(LedgerOpenRequestMsg {
            protocol_version: 1,
            min_protocol_version: 1,
            features: 0,
            public_key: self.our_node_id,
            partner_id: partner_node_id,
            ledger_address: ledger_addr_str,
            funding_txid,
            funding_vout,
        });

        // Calculate message hash for tracking
        use lightning::util::ser::Writeable;
        let message_hash = {
            let mut buf = Vec::new();
            init_msg_for_broadcast.write(&mut buf).map_err(|e| {
                DepositsError::InvalidState(format!("Failed to serialize message: {}", e))
            })?;
            use bitcoin::hashes::{Hash, sha256};
            sha256::Hash::hash(&buf).to_byte_array()
        };

        // Store message for broadcasting (so broadcast_message_to_other_partners can find it)
        // For LedgerOpenRequest, prev_hash is [0u8; 32] (genesis) and new_hash is the ledger's current hash
        let (prev_hash, new_hash, sequence_number) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                // LedgerOpenRequest uses 0-based sequence for SignedAuditUpdate
                let seq = ledger.history.len() as u64; // 0-based (index of entry being added)
                ([0u8; 32], ledger.tail_hash(), seq)
            } else {
                ([0u8; 32], [0u8; 32], 0) // Fallback if ledger not found
            }
        };
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, init_msg_for_broadcast, prev_hash, new_hash, sequence_number));
        }

        // Broadcast as signed update to all auditors
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(
                self.logger,
                "Failed to broadcast LedgerOpenRequest to auditors: {}",
                e
            );
        }

        Ok(())
    }
}
