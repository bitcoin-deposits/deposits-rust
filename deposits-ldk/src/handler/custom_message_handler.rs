// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! CustomMessageHandler implementation for the Bitcoin Deposits protocol.
//!
//! This module contains the Lightning network custom message handling traits
//! for receiving and dispatching Bitcoin Deposits protocol messages.

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::util::ser::LengthLimitedRead;
use lightning_types::features::{InitFeatures, NodeFeatures};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::core::DepositsHandler;
use super::messages::DepositsMessage;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> CustomMessageReader for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    type CustomMessage = DepositsMessage;

    fn read<R: LengthLimitedRead>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        self.message_reader.read(message_type, buffer)
    }
}

impl<L: Deref + Clone + Send + Sync> CustomMessageHandler for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        // Log incoming message in base64 for test replay
        // Format: PEER_MSG|<sender_pubkey>|<message_type_hex>|<variant_name>|<base64_encoded_message>
        let encoded_bytes = msg.encode();
        let base64_msg = BASE64.encode(&encoded_bytes);
        log_info!(
            self.logger,
            "PEER_MSG|{}|0x{:04x}|{}|{}",
            sender_node_id,
            msg.message_type(),
            msg.variant_name(),
            base64_msg
        );

        // On first message from this peer after (re)connection, refresh commitment to catch up
        let should_refresh = {
            let mut refreshed = self.peers_refreshed_after_reconnect.lock().unwrap();
            if !refreshed.contains(&sender_node_id) {
                refreshed.insert(sender_node_id);
                true
            } else {
                false
            }
        };

        if should_refresh {
            log_debug!(self.logger, "First message from {} since reconnect, refreshing commitment...", sender_node_id);
            if let Err(e) = self.refresh_reserves_commitment(sender_node_id) {
                log_debug!(
                    self.logger,
                    "Could not refresh reserves commitment with {} after reconnect: {:?}",
                    sender_node_id,
                    e
                );
            } else {
                log_info!(self.logger, "Successfully refreshed commitment with {} after reconnect", sender_node_id);
            }
        }

        self.process_message(msg, sender_node_id)
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut result = Vec::new();

        // Only return messages for connected peers - messages for disconnected peers stay in queue
        // LDK drops messages for disconnected peers, so we must hold them until reconnection
        let connected = self.connected_peers.lock().unwrap().clone();
        let mut guard = self.outbound_messages.lock().unwrap();

        // Collect peer IDs for connected peers with messages
        let peers_to_drain: Vec<PublicKey> = guard.keys()
            .filter(|peer_id| connected.contains(peer_id))
            .cloned()
            .collect();

        // Only drain messages for connected peers
        for peer_id in peers_to_drain {
            if let Some(messages) = guard.remove(&peer_id) {
                for message in messages {
                    result.push((peer_id, message));
                }
            }
        }

        result
    }

    fn provided_node_features(&self) -> NodeFeatures {
        let features = NodeFeatures::empty();

        // For now, we rely on Lightning's default handling of unknown custom message types
        // Bitcoin Deposits uses message types in 0x8000-0x80FF range which Lightning should
        // automatically route to custom message handlers

        // Enable unknown features support to signal we can handle custom protocols
        // This allows peers to send us custom messages without disconnecting

        log_debug!(
            self.logger,
            "₿ Providing node features for Bitcoin Deposits protocol (custom message types 0x8000-0x80FF)"
        );

        features
    }

    fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
        let features = InitFeatures::empty();

        // For Bitcoin Deposits protocol, we rely on Lightning's built-in custom message routing
        // Custom message types in 0x8000-0x80FF range should be automatically handled

        // Check if we have an active channel ledger with this peer for future enhancements
        let has_ledger = self.ledgers.lock().unwrap().contains_key(&(self.our_node_id, their_node_id));

        log_debug!(
            self.logger,
            "₿ Providing init features to {} for Bitcoin Deposits protocol (has_ledger: {})",
            their_node_id,
            has_ledger
        );

        features
    }

    fn peer_connected(
        &self,
        their_node_id: PublicKey,
        msg: &lightning::ln::msgs::Init,
        inbound: bool,
    ) -> Result<(), ()> {
        log_debug!(
            self.logger,
            "Bitcoin Deposits peer connected: {} (inbound: {})",
            their_node_id,
            inbound
        );
        // Track this peer as connected for message delivery
        self.connected_peers.lock().unwrap().insert(their_node_id);

        // Check if peer supports Bitcoin Deposits protocol
        if self.peer_supports_protocol(&msg.features) {
            log_info!(
                self.logger,
                "Peer {} supports Bitcoin Deposits protocol",
                their_node_id
            );
        }

        // Check if we have an undelivered consent request for this peer and resend it
        let undelivered = {
            let requests = self.undelivered_consent_requests.lock().unwrap();
            requests.get(&their_node_id).cloned()
        };

        if let Some((_message_hash, consent_request)) = undelivered {
            log_info!(
                self.logger,
                "🔄 Resending undelivered consent request to reconnected peer {}",
                their_node_id
            );
            // Resend the consent request - the original caller is still waiting for the response
            if let Err(e) = self.send_message(their_node_id, consent_request) {
                log_error!(
                    self.logger,
                    "Failed to resend consent request to {}: {:?}",
                    their_node_id,
                    e
                );
            }
        }

        // Check if we have pending outbound messages for this peer that need to be resent
        let pending_count = {
            let outbound = self.outbound_messages.lock().unwrap();
            outbound.get(&their_node_id).map(|msgs| msgs.len()).unwrap_or(0)
        };

        if pending_count > 0 {
            log_info!(
                self.logger,
                "🔄 Peer {} reconnected with {} pending outbound messages - triggering resend",
                their_node_id,
                pending_count
            );
            // Trigger the message processing loop to send pending messages
            // Use message type 0x0000 as a placeholder since we're just triggering processing
            self.trigger_immediate_send(their_node_id, 0x0000);
        }

        Ok(())
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        log_debug!(
            self.logger,
            "Bitcoin Deposits peer disconnected: {}",
            their_node_id
        );
        // Remove from connected peers - messages for this peer will be held until reconnection
        self.connected_peers.lock().unwrap().remove(&their_node_id);

        // NOTE: We intentionally do NOT clear pending outbound messages on disconnect.
        // Messages will be delivered when the peer reconnects. This is important for
        // consent requests and other messages that should survive temporary disconnections.
        // The alternative (clearing messages) causes consent timeouts when peers briefly disconnect.
    }
}
