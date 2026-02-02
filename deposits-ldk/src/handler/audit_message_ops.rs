// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Audit message handling for the Bitcoin Deposits protocol.
//!
//! This module handles third-party audit messages - ledger updates for channels
//! we're not directly part of but are monitoring as an auditor.

use bitcoin::secp256k1::PublicKey;
use std::sync::{Arc, RwLock};

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use deposits_core::{Ledger, LedgerRole};
use super::messages::DepositsMessage;
use super::ledger_ext::LedgerExt;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Handle a third-party audit message (ledger update for a channel we're not part of)
    pub(super) fn handle_third_party_audit_message(
        &self,
        message: &DepositsMessage,
        sender: PublicKey,
    ) -> Result<(), DepositsError> {
        // V2: Audit messages come via SyncResponse with Vec<SignedLedgerUpdate>
        if let DepositsMessage::SyncResponse(ref sync_response) = message {
            log_info!(
                self.logger,
                "📋 AUDIT: Received sync response with {} updates from {} for operator {} -> partner {}",
                sync_response.updates.len(),
                sender,
                sync_response.operator_id,
                sync_response.reserves_id
            );

            // Process each signed update
            for signed_update in &sync_response.updates {
                log_info!(
                    self.logger,
                    "📋 AUDIT: Processing signed update seq={}",
                    signed_update.sequence_number
                );
                self.verify_and_store_signed_update(signed_update.clone())?;
            }
            return Ok(());
        }

        // V2: LedgerUpdateMsg no longer carries full signed data for audit purposes
        // New operations use the regular LedgerUpdate flow, audit sync uses SyncResponse
        if let DepositsMessage::LedgerUpdate(ref update_msg) = message {
            log_info!(
                self.logger,
                "📋 AUDIT: Received ledger update seq={} from operator {} -> partner {} (will be processed via normal flow)",
                update_msg.sequence_number,
                update_msg.operator_id,
                update_msg.reserves_id
            );
            // In V2, individual LedgerUpdate messages are for new operations, not audit sync
            // Return Ok to indicate we've seen it, but don't try to store as signed update
            return Ok(());
        }

        // The sender is the operator of the ledger being audited
        // Extract reserves_id from the message
        let reserves_id = match message.reserves_id() {
            Some(id) => id,
            None => {
                log_debug!(
                    self.logger,
                    "📋 AUDIT: Message type {:#06x} doesn't contain reserves_id, skipping audit storage",
                    message.message_type()
                );
                return Ok(());
            }
        };

        let operator_id = sender;

        // Don't create audit ledgers for our own direct ledgers
        if operator_id == self.our_node_id || reserves_id == self.our_node_id.to_string() {
            log_debug!(
                self.logger,
                "📋 AUDIT: Skipping audit ledger creation - we are part of this ledger (operator={}, partner={})",
                operator_id,
                reserves_id
            );
            return Ok(());
        }

        log_info!(
            self.logger,
            "📋 AUDIT: Received third-party message type {:#06x} for ledger (operator={}, partner={})",
            message.message_type(),
            operator_id,
            reserves_id
        );


        // Get or create audit ledger for this (operator, partner) pair
        let reserves_id_for_closure = reserves_id.clone();
        let ledger_arc = {
            let mut ledgers = self.ledgers.lock().unwrap();
            ledgers
                .entry((operator_id, reserves_id.clone()))
                .or_insert_with(|| {
                    use bitcoin::secp256k1::{Secp256k1, SecretKey};
                    use bitcoin::hashes::{sha256, Hash};
                    // Create a placeholder ledger - we don't know the actual ledger address
                    // but that's okay for audit purposes
                    // Generate a deterministic placeholder address from the operator and partner IDs
                    let secp = Secp256k1::new();
                    let mut hash_data = Vec::new();
                    hash_data.extend_from_slice(&operator_id.serialize());
                    hash_data.extend_from_slice(reserves_id_for_closure.as_bytes());
                    let hash = sha256::Hash::hash(&hash_data);
                    let secret_key = SecretKey::from_slice(&hash[..]).expect("Valid hash");
                    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                    let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
                    let compressed_pk = bitcoin::key::CompressedPublicKey::try_from(bitcoin_pubkey)
                        .expect("Valid public key");
                    let placeholder_address = bitcoin::Address::p2wpkh(&compressed_pk, bitcoin::KnownHrp::Regtest);

                    Arc::new(RwLock::new(Ledger::new(
                        operator_id,
                        reserves_id_for_closure.clone(),
                        LedgerRole::Auditor,
                        Vec::new(), // No quorum members for audit ledgers
                        placeholder_address.to_string(),
                        0, // genesis_block: LDK doesn't have direct block height access
                    )))
                })
                .clone()
        };

        // Apply the message to the audit ledger
        // Handshake needs special handling to set the ledger address
        if let DepositsMessage::Handshake(ref handshake_msg) = message {
            let mut ledger = ledger_arc.write().unwrap();

            // For LDK, ledger address is derived from funding UTXO (placeholder for audit ledgers)
            // In a full implementation, this would compute the taproot address
            let ledger_address = format!("bcrt1q{}audit", hex::encode(&handshake_msg.funding_txid[..4]));
            ledger.state.ledger_address = ledger_address;

            // Apply Handshake if this is the first update
            if ledger.history.is_empty() {
                if let Err(e) = ledger.append_mut(DepositsMessage::Handshake(handshake_msg.clone())) {
                    log_error!(self.logger, "📋 AUDIT: Failed to apply Handshake: {}", e);
                }
            }

            log_info!(self.logger, "📋 AUDIT: Handshake processed (operator={}, partner={})",
                     operator_id, reserves_id);

            drop(ledger);
            let ledger_for_persist = ledger_arc.read().unwrap();
            if let Err(e) = self.persist_audit_ledger_state(operator_id, &reserves_id, &ledger_for_persist) {
                log_error!(self.logger, "📋 AUDIT: Failed to persist audit ledger: {}", e);
            }
        } else if message.is_ledger_operation() {
            // Unified handling for all ledger operations (V2 LedgerUpdate)
            // The ledger.append_mut() handles all message types via apply_operation()
            let mut ledger = ledger_arc.write().unwrap();
            let result = ledger.append_mut(message.clone());
            if let Err(e) = result {
                log_error!(self.logger, "📋 AUDIT: Failed to apply message type {:#06x} to audit ledger: {}", message.message_type(), e);
            } else {
                log_debug!(self.logger, "📋 AUDIT: Message type {:#06x} applied to audit ledger", message.message_type());
                drop(ledger);
                let ledger_for_persist = ledger_arc.read().unwrap();
                if let Err(e) = self.persist_audit_ledger_state(operator_id, &reserves_id, &ledger_for_persist) {
                    log_error!(self.logger, "📋 AUDIT: Failed to persist audit ledger: {}", e);
                }
            }
        } else {
            log_debug!(self.logger, "📋 AUDIT: Skipping non-ledger message type {:#06x}", message.message_type());
        }

        Ok(())
    }
}
