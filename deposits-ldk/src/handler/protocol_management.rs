// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Protocol management operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for:
//! - Registering/unregistering protocol instances
//! - Accessing logger and quorum manager
//! - Quorum join requests and state sync

use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, QuorumJoinRequestMsg};
use super::protocol_stub::DepositsProtocol;
use deposits_core::quorum::QuorumManager;
use lightning::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Register a protocol instance for a specific partner
    pub fn add_protocol(
        &self,
        partner_node_id: PublicKey,
        protocol: Arc<DepositsProtocol<L>>,
    ) {
        self.protocols.lock().unwrap().insert(partner_node_id, protocol);

        log_info!(
            self.logger,
            "Bitcoin Deposits protocol registered for partner: {}",
            partner_node_id
        );
    }

    /// Remove protocol instance for a partner
    pub fn remove_protocol(&self, partner_node_id: &PublicKey) {
        self.protocols.lock().unwrap().remove(partner_node_id);

        log_info!(
            self.logger,
            "Bitcoin Deposits protocol unregistered for partner: {}",
            partner_node_id
        );
    }

    /// Get logger reference
    pub fn logger(&self) -> &L {
        &self.logger
    }

    /// Get quorum manager reference
    pub fn quorum_manager(&self) -> &QuorumManager {
        &self.quorum_manager
    }

    /// Request to join a quorum as an auditor
    ///
    /// Sends a join request to the specified target (operator or partner) to join
    /// their ledger's quorum. Upon acceptance, we will receive state sync messages
    /// with historical signed updates.
    ///
    /// # Arguments
    /// * `target_node_id` - The node ID to send the join request to (operator or partner)
    /// * `operator_id` - The operator's public key for the ledger
    /// * `partner_id` - The partner's public key for the ledger
    pub fn request_join_quorum(
        &self,
        target_node_id: PublicKey,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) -> Result<(), DepositsError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: self.our_node_id,
            operator_id,
            partner_id,
            protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
            timestamp,
            signature: [0u8; 64],
        };

        log_info!(
            self.logger,
            "📋 QUORUM: Sending join request to {} for ledger ({}, {})",
            target_node_id,
            operator_id,
            partner_id
        );

        // Queue the message for sending
        self.outbound_messages
            .lock()
            .unwrap()
            .entry(target_node_id)
            .or_insert_with(Vec::new)
            .push(DepositsMessage::QuorumJoinRequest {
                requester_pubkey: join_request.requester_pubkey,
                operator_id: join_request.operator_id,
                partner_id: join_request.partner_id,
                protocol_version: join_request.protocol_version,
                timestamp: join_request.timestamp,
                signature: join_request.signature,
            });

        Ok(())
    }

    /// Send state sync to a new quorum member
    ///
    /// Called after accepting a join request to send the new member all historical
    /// signed updates for the ledger they're joining.
    pub(super) fn send_state_sync_to_member(
        &self,
        member_pubkey: PublicKey,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) {
        const BATCH_SIZE: usize = 100; // Send updates in batches to avoid huge messages

        // Check our own ledgers first (we might be operator or partner)
        let updates_to_send: Vec<deposits_core::SignedLedgerUpdate> = {
            // Try ledgers first (our own ledgers)
            let ledgers = self.ledgers.lock().unwrap();
            if ledgers.contains_key(&(operator_id, partner_id)) {
                // We are the operator or partner - get updates from our ledger
                drop(ledgers);

                // For our own ledgers, we need to get updates from the ledger's signed update log
                let logs = self.signed_update_logs.lock().unwrap();
                if let Some(log) = logs.get(&(operator_id, partner_id)) {
                    log.updates.clone()
                } else {
                    Vec::new()
                }
            } else {
                drop(ledgers);

                // Check if we have third-party audit copy
                let logs = self.signed_update_logs.lock().unwrap();
                if let Some(log) = logs.get(&(operator_id, partner_id)) {
                    log.updates.clone()
                } else {
                    Vec::new()
                }
            }
        };

        if updates_to_send.is_empty() {
            log_info!(
                self.logger,
                "📋 QUORUM: No updates to sync to {} for ledger ({}, {})",
                member_pubkey,
                operator_id,
                partner_id
            );

            // Send empty final batch to indicate sync complete
            let sync_msg = DepositsMessage::QuorumStateSync {
                operator_id,
                partner_id,
                updates: Vec::new(),
                start_sequence: 0,
                is_final: true,
            };

            self.outbound_messages
                .lock()
                .unwrap()
                .entry(member_pubkey)
                .or_insert_with(Vec::new)
                .push(sync_msg);

            return;
        }

        log_info!(
            self.logger,
            "📋 QUORUM: Sending {} updates to {} for ledger ({}, {})",
            updates_to_send.len(),
            member_pubkey,
            operator_id,
            partner_id
        );

        // Convert to SignedAuditUpdateMsg and send in batches
        use super::messages::{SignedUpdateMsg, LedgerOperation};

        let total_batches = (updates_to_send.len() + BATCH_SIZE - 1) / BATCH_SIZE;

        for (batch_idx, chunk) in updates_to_send.chunks(BATCH_SIZE).enumerate() {
            let audit_updates: Vec<SignedUpdateMsg> = chunk.iter().map(|update| {
                SignedUpdateMsg {
                    message: update.message.clone(),
                    message_type: update.message_type,
                    operator_signature: update.operator_signature,
                    partner_signature: Some(update.partner_signature),
                    operator_pubkey: update.operator_pubkey,
                    partner_pubkey: update.partner_pubkey,
                    sequence_number: update.sequence_number,
                    previous_state_hash: update.previous_state_hash,
                    current_state_hash: update.current_state_hash,
                    timestamp: update.timestamp,
                    operation: LedgerOperation::ReservesRemove, // Placeholder - actual operation is in message bytes
                }
            }).collect();

            let start_sequence = chunk.first().map(|u| u.sequence_number).unwrap_or(0);
            let is_final = batch_idx == total_batches - 1;

            log_debug!(
                self.logger,
                "📋 QUORUM: Sending batch {}/{} ({} updates, start_seq={}, is_final={})",
                batch_idx + 1,
                total_batches,
                audit_updates.len(),
                start_sequence,
                is_final
            );

            let sync_msg = DepositsMessage::QuorumStateSync {
                operator_id,
                partner_id,
                updates: audit_updates,
                start_sequence,
                is_final,
            };

            self.outbound_messages
                .lock()
                .unwrap()
                .entry(member_pubkey)
                .or_insert_with(Vec::new)
                .push(sync_msg);
        }
    }

    /// Get protocol instance for a partner
    pub fn get_protocol(&self, partner_node_id: &PublicKey) -> Option<Arc<DepositsProtocol<L>>> {
        self.protocols.lock().unwrap().get(partner_node_id).cloned()
    }

    /// Generate a unique request ID for tracking pending requests
    pub(super) fn generate_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Helper to get or create a protocol instance for a partner
    pub(super) fn get_or_create_protocol(
        &self,
        partner_node_id: PublicKey,
    ) -> Result<Arc<DepositsProtocol<L>>, DepositsError> {
        // Check if we already have a protocol for this partner
        if let Some(protocol) = self.get_protocol(&partner_node_id) {
            return Ok(protocol);
        }

        // Create a new protocol instance
        // Note: In production, we'd need the node's actual secret key
        // For now, we'll use a dummy key - this needs to be fixed
        use bitcoin::secp256k1::SecretKey;
        use crate::types::DynStore;

        let dummy_secret_key = SecretKey::from_slice(&[1u8; 32])
            .map_err(|_| DepositsError::InvalidSecretKey)?;

        // Use simple in-memory store for testing
        #[cfg(any(test, feature = "testing"))]
        let store: Arc<DynStore> = {
            use lightning::util::persist::KVStore;
            use lightning::io;

            #[derive(Debug)]
            struct MemoryStore(RwLock<HashMap<String, Vec<u8>>>);

            impl KVStore for MemoryStore {
                fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Result<Vec<u8>, lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.read().unwrap().get(&full_key).cloned()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))
                }

                fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8]) -> Result<(), lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.write().unwrap().insert(full_key, buf.to_vec());
                    Ok(())
                }

                fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool) -> Result<(), lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.write().unwrap().remove(&full_key);
                    Ok(())
                }

                fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
                    let prefix = format!("{}:{}:", primary_namespace, secondary_namespace);
                    let keys: Vec<String> = self.0.read().unwrap()
                        .keys()
                        .filter(|k| k.starts_with(&prefix))
                        .map(|k| k[prefix.len()..].to_string())
                        .collect();
                    Ok(keys)
                }
            }

            Arc::new(MemoryStore(RwLock::new(HashMap::new())))
        };

        #[cfg(not(any(test, feature = "testing")))]
        let store: Arc<DynStore> = {
            use lightning::util::persist::KVStore;
            use lightning::io;

            #[derive(Debug)]
            struct MemoryStore(RwLock<HashMap<String, Vec<u8>>>);

            impl KVStore for MemoryStore {
                fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Result<Vec<u8>, lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.read().unwrap().get(&full_key).cloned()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))
                }

                fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8]) -> Result<(), lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.write().unwrap().insert(full_key, buf.to_vec());
                    Ok(())
                }

                fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool) -> Result<(), lightning::io::Error> {
                    let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                    self.0.write().unwrap().remove(&full_key);
                    Ok(())
                }

                fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
                    let prefix = format!("{}:{}:", primary_namespace, secondary_namespace);
                    let keys: Vec<String> = self.0.read().unwrap()
                        .keys()
                        .filter(|k| k.starts_with(&prefix))
                        .map(|k| k[prefix.len()..].to_string())
                        .collect();
                    Ok(keys)
                }
            }

            Arc::new(MemoryStore(RwLock::new(HashMap::new())))
        };

        let protocol = Arc::new(DepositsProtocol::new(
            dummy_secret_key,
            store,
            self.logger.clone(),
        ));

        // Register the protocol
        self.add_protocol(partner_node_id, Arc::clone(&protocol));

        Ok(protocol)
    }
}
