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
use std::sync::Arc;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, CoordinationMsg, CoordinationResponseMsg};
use super::protocol_stub::DepositsProtocol;
use deposits_core::quorum::QuorumManager;
use deposits_core::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
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
    /// * `reserves_id` - The partner's public key for the ledger
    pub fn request_join_quorum(
        &self,
        target_node_id: PublicKey,
        operator_id: PublicKey,
        reserves_id: PublicKey,
    ) -> Result<(), DepositsError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        log_info!(
            self.logger,
            "📋 QUORUM: Sending join request to {} for ledger ({}, {})",
            target_node_id,
            operator_id,
            reserves_id
        );

        // Queue the message for sending (V2 format)
        self.outbound_messages
            .lock()
            .unwrap()
            .entry(target_node_id)
            .or_insert_with(Vec::new)
            .push(DepositsMessage::Coordination(CoordinationMsg::QuorumJoinRequest {
                requester_pubkey: self.our_node_id,
                operator_id,
                reserves_id,
                protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
                timestamp,
                signature: [0u8; 64],
            }));

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
        reserves_id: PublicKey,
    ) {
        const BATCH_SIZE: usize = 100; // Send updates in batches to avoid huge messages

        // Check our own ledgers first (we might be operator or partner)
        let updates_to_send: Vec<deposits_core::SignedLedgerUpdate> = {
            // Try ledgers first (our own ledgers)
            let ledgers = self.ledgers.lock().unwrap();
            if ledgers.contains_key(&(operator_id, reserves_id)) {
                // We are the operator or partner - get updates from our ledger
                drop(ledgers);

                // For our own ledgers, we need to get updates from the ledger's signed update log
                let logs = self.signed_update_logs.lock().unwrap();
                if let Some(log) = logs.get(&(operator_id, reserves_id)) {
                    log.updates.clone()
                } else {
                    Vec::new()
                }
            } else {
                drop(ledgers);

                // Check if we have third-party audit copy
                let logs = self.signed_update_logs.lock().unwrap();
                if let Some(log) = logs.get(&(operator_id, reserves_id)) {
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
                reserves_id
            );

            // Send empty final batch to indicate sync complete
            let sync_msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::QuorumStateSync {
                request_hash: [0u8; 32],
                operator_id,
                reserves_id,
                updates: Vec::new(),
                start_sequence: 0,
                is_final: true,
            });

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
            reserves_id
        );

        // Send updates in batches - updates_to_send is Vec<deposits_core::SignedLedgerUpdate> from types.rs
        // which is the same type used in the message (bytes are bytes, no conversion needed)
        let total_batches = (updates_to_send.len() + BATCH_SIZE - 1) / BATCH_SIZE;

        for (batch_idx, chunk) in updates_to_send.chunks(BATCH_SIZE).enumerate() {
            let start_sequence = chunk.first().map(|u| u.sequence_number).unwrap_or(0);
            let is_final = batch_idx == total_batches - 1;

            log_debug!(
                self.logger,
                "📋 QUORUM: Sending batch {}/{} ({} updates, start_seq={}, is_final={})",
                batch_idx + 1,
                total_batches,
                chunk.len(),
                start_sequence,
                is_final
            );

            let sync_msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::QuorumStateSync {
                request_hash: [0u8; 32],
                operator_id,
                reserves_id,
                updates: chunk.to_vec(),
                start_sequence,
                is_final,
            });

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
}
