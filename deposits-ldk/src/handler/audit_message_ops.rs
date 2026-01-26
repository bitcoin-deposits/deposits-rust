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
        // Handle LedgerUpdate messages specially - they contain signatures
        if let DepositsMessage::LedgerUpdate(ref update_msg) = message {
            log_info!(
                self.logger,
                "📋 AUDIT: Received ledger update seq={} from operator {} -> partner {}",
                update_msg.sequence_number,
                update_msg.operator_pubkey,
                update_msg.partner_pubkey
            );

            // Convert to SignedLedgerUpdate and verify/store
            let signed_update = deposits_core::SignedLedgerUpdate {
                message: update_msg.message.clone(),
                message_type: update_msg.message_type,
                operator_signature: update_msg.operator_signature,
                partner_signature: update_msg.partner_signature.unwrap_or([0u8; 64]),
                operator_pubkey: update_msg.operator_pubkey,
                partner_pubkey: update_msg.partner_pubkey,
                sequence_number: update_msg.sequence_number,
                previous_state_hash: update_msg.previous_state_hash,
                current_state_hash: update_msg.current_state_hash,
                timestamp: update_msg.timestamp,
            };

            // Verify and store the signed update
            return self.verify_and_store_signed_update(signed_update);
        }

        // The sender is the operator of the ledger being audited
        // Extract partner_id from the message
        let partner_id = match message.partner_id() {
            Some(id) => id,
            None => {
                log_debug!(
                    self.logger,
                    "📋 AUDIT: Message type {:#06x} doesn't contain partner_id, skipping audit storage",
                    message.message_type()
                );
                return Ok(());
            }
        };

        let operator_id = sender;

        // Don't create audit ledgers for our own direct ledgers
        if operator_id == self.our_node_id || partner_id == self.our_node_id {
            log_debug!(
                self.logger,
                "📋 AUDIT: Skipping audit ledger creation - we are part of this ledger (operator={}, partner={})",
                operator_id,
                partner_id
            );
            return Ok(());
        }

        log_info!(
            self.logger,
            "📋 AUDIT: Received third-party message type {:#06x} for ledger (operator={}, partner={})",
            message.message_type(),
            operator_id,
            partner_id
        );


        // Get or create audit ledger for this (operator, partner) pair
        let ledger_arc = {
            let mut ledgers = self.ledgers.lock().unwrap();
            ledgers
                .entry((operator_id, partner_id))
                .or_insert_with(|| {
                    use bitcoin::secp256k1::{Secp256k1, SecretKey};
                    use bitcoin::hashes::{sha256, Hash};
                    // Create a placeholder ledger - we don't know the actual ledger address
                    // but that's okay for audit purposes
                    // Generate a deterministic placeholder address from the operator and partner IDs
                    let secp = Secp256k1::new();
                    let mut hash_data = Vec::new();
                    hash_data.extend_from_slice(&operator_id.serialize());
                    hash_data.extend_from_slice(&partner_id.serialize());
                    let hash = sha256::Hash::hash(&hash_data);
                    let secret_key = SecretKey::from_slice(&hash[..]).expect("Valid hash");
                    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                    let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
                    let compressed_pk = bitcoin::key::CompressedPublicKey::try_from(bitcoin_pubkey)
                        .expect("Valid public key");
                    let placeholder_address = bitcoin::Address::p2wpkh(&compressed_pk, bitcoin::KnownHrp::Regtest);

                    Arc::new(RwLock::new(Ledger::new(
                        operator_id,
                        partner_id,
                        LedgerRole::Auditor,
                        Vec::new(), // No collateral partners for audit ledgers
                        placeholder_address.to_string(),
                    )))
                })
                .clone()
        };

        // Apply the message to the audit ledger
        // Handshake needs special handling to set the ledger address
        if let DepositsMessage::Handshake(ref handshake_msg) = message {
            let mut ledger = ledger_arc.write().unwrap();

            // Parse and validate the ledger address
            match handshake_msg.ledger_address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
                Ok(unchecked_addr) => {
                    match unchecked_addr.require_network(bitcoin::Network::Regtest) {
                        Ok(validated_addr) => {
                            ledger.state.ledger_address = validated_addr.to_string();

                            // Apply Handshake if this is the first update
                            if ledger.history.is_empty() {
                                if let Err(e) = ledger.append_v1_mut(DepositsMessage::Handshake(handshake_msg.clone())) {
                                    log_error!(self.logger, "📋 AUDIT: Failed to apply Handshake: {}", e);
                                }
                            }

                            log_info!(self.logger, "📋 AUDIT: Handshake processed (operator={}, partner={})",
                                     operator_id, partner_id);

                            drop(ledger);
                            let ledger_for_persist = ledger_arc.read().unwrap();
                            if let Err(e) = self.persist_audit_ledger_state(operator_id, partner_id, &ledger_for_persist) {
                                log_error!(self.logger, "📋 AUDIT: Failed to persist audit ledger: {}", e);
                            }
                        }
                        Err(e) => {
                            log_error!(self.logger, "📋 AUDIT: Invalid network for ledger address: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log_error!(self.logger, "📋 AUDIT: Failed to parse ledger address: {}", e);
                }
            }
        } else if message.is_ledger_operation() {
            // Unified handling for all ledger operations (V2 LedgerUpdate)
            // The ledger.append_v1_mut() handles all message types via apply_operation()
            let mut ledger = ledger_arc.write().unwrap();
            let result = ledger.append_v1_mut(message.clone());
            if let Err(e) = result {
                log_error!(self.logger, "📋 AUDIT: Failed to apply message type {:#06x} to audit ledger: {}", message.message_type(), e);
            } else {
                log_debug!(self.logger, "📋 AUDIT: Message type {:#06x} applied to audit ledger", message.message_type());
                drop(ledger);
                let ledger_for_persist = ledger_arc.read().unwrap();
                if let Err(e) = self.persist_audit_ledger_state(operator_id, partner_id, &ledger_for_persist) {
                    log_error!(self.logger, "📋 AUDIT: Failed to persist audit ledger: {}", e);
                }
            }
        } else {
            log_debug!(self.logger, "📋 AUDIT: Skipping non-ledger message type {:#06x}", message.message_type());
        }

        Ok(())
    }
}
