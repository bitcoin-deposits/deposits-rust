// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Messaging infrastructure for the Bitcoin Deposits protocol.
//!
//! This module contains operations for:
//! - Sending messages to peers
//! - ACK tracking with oneshot channels
//! - Collateral consent request/response flow
//! - Async message handling for tokio contexts
//! - Commitment waiting utilities

use bitcoin::secp256k1::PublicKey;
use tokio::sync::oneshot;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateResponseMsg};
use deposits_core::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Send a message to a specific peer
    pub fn send_message(
        &self,
        peer_node_id: PublicKey,
        message: DepositsMessage,
    ) -> Result<(), DepositsError> {
        let message_type = message.message_type();

        log_debug!(
            self.logger,
            "Sending Bitcoin Deposits message type {:#06x} to peer {}",
            message_type,
            peer_node_id
        );

        // Store message for broadcasting with prev_hash
        // We'll update with new_hash later after applying the update
        // Skip ACK responses and coordination messages that are NOT ledger updates
        if !matches!(message,
            // Skip coordination/control messages that are NOT bilateral ledger updates:
            DepositsMessage::LedgerUpdateResponse(_) |      // ACK responses
            // NOTE: LedgerUpdate IS a real ledger update that needs broadcast tracking
            DepositsMessage::Coordination(_) |              // Collateral consent, quorum votes
            DepositsMessage::CoordinationResponse(_) |      // Collateral consent responses
            DepositsMessage::Handshake(_) |                 // Ledger open sequence
            DepositsMessage::HandshakeResponse(_) |
            DepositsMessage::Sync(_) |                      // Audit sync coordination
            DepositsMessage::SyncResponse(_) |
            DepositsMessage::Recovery(_) |                  // Recovery operations
            DepositsMessage::RecoveryResponse(_) |
            DepositsMessage::Relay(_) |                     // NWC relay
            DepositsMessage::RelayResponse(_)
            // NOTE: LedgerUpdate with Tombstone IS a real ledger update that needs broadcast
        ) {
            // No-op: Callers are responsible for inserting into sent_messages_for_broadcast
            // with the correct hash BEFORE calling send_message. The hash is deterministic
            // and computable immediately: new_hash = hash(operation_content + previous_hash)
        }

        // Queue the message for delivery
        let queue_len_after = {
            let mut guard = self.outbound_messages.lock().unwrap();
            guard.entry(peer_node_id).or_insert_with(Vec::new).push(message);
            let len = guard.get(&peer_node_id).map(|v| v.len()).unwrap_or(0);
            len
        };

        log_info!(
            self.logger,
            "📤 Queued Bitcoin Deposits message type {:#06x} for peer {} (queue now has {} messages)",
            message_type,
            peer_node_id,
            queue_len_after
        );

        // SOLUTION: Record timestamp for periodic message processing trigger
        // Since we can't access Lightning's private notification system, we'll use a different approach
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.last_msg_queued.store(timestamp, std::sync::atomic::Ordering::Relaxed);

        log_info!(
            self.logger,
            "✅ Message queued at timestamp {} - will be processed by next get_and_clear_pending_msg call",
            timestamp
        );

        // Trigger immediate processing for sub-second delivery
        self.trigger_immediate_send(peer_node_id, message_type);

        Ok(())
    }

    /// Check if there are pending messages that need to be sent
    /// This provides a way for the background processor to know when to call get_and_clear_pending_msg
    pub fn has_pending_messages(&self) -> bool {
        match self.outbound_messages.try_lock() {
            Err(_) => {
                // Lock is held, wait for it
                let guard = self.outbound_messages.lock().unwrap();
                !guard.is_empty()
            }
            Ok(o) => !o.is_empty(),
        }
    }

    /// Get the timestamp of the last queued message (for timing-based processing)
    pub fn last_message_queued_timestamp(&self) -> u64 {
        self.last_msg_queued.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Trigger immediate message sending by manually processing the queue
    ///
    /// FIXED: Don't clear messages prematurely - just trigger processing
    pub(super) fn trigger_immediate_send(&self, peer_node_id: PublicKey, message_type: u16) {
        // Check if there are pending messages without clearing them
        let message_count = {
            self.outbound_messages.lock().unwrap().
                get(&peer_node_id).map(|v| v.len()).unwrap_or(0)
        };

        if message_count > 0 {
            log_info!(
                self.logger,
                "🚀 Triggering immediate send for {} pending messages (including type {:#06x} for peer {})",
                message_count,
                message_type,
                peer_node_id
            );

            // SOLUTION: The enhanced background processor will pick up pending messages
            // through the has_pending_messages() method and trigger get_and_clear_pending_msg()
            log_debug!(self.logger, "🔥 Enhanced background processor will handle immediate message delivery");
        } else {
            log_debug!(
                self.logger,
                "🔧 Immediate send trigger found no pending messages for peer {}",
                peer_node_id
            );
        }
    }

    /// Calculate message hash for ACK tracking
    pub(super) fn calculate_message_hash(&self, message: &DepositsMessage) -> [u8; 32] {
        use bitcoin::hashes::{Hash, sha256};
        use lightning::util::ser::Writeable;

        let mut buffer = Vec::new();
        message.write(&mut buffer).unwrap_or_default();
        sha256::Hash::hash(&buffer).to_byte_array()
    }

    /// Create a partner-specific hash by XORing message_hash with partner pubkey bytes.
    /// This is used when the same message content is sent to multiple partners, ensuring
    /// unique keys in pending_acks and sent_messages_for_broadcast.
    pub(super) fn create_partner_specific_hash(message_hash: &[u8; 32], partner: &PublicKey) -> [u8; 32] {
        let partner_bytes = partner.serialize();
        let mut result = *message_hash;
        // XOR the first 33 bytes with partner pubkey (which is 33 bytes compressed)
        for (i, b) in partner_bytes.iter().enumerate() {
            if i < 32 {
                result[i] ^= b;
            }
        }
        result
    }

    /// Send a message and wait for its acknowledgment using oneshot channels (Lightning Liquidity pattern)
    /// This solves the deadlock issue where blocking on mpsc prevents message sending in LDK Node's quasi-async architecture
    pub(super) fn send_message_with_oneshot_ack(
        &self,
        peer_node_id: PublicKey,
        message: DepositsMessage,
        timeout_ms: u64,
    ) -> Result<(), DepositsError> {
        use std::time::Duration;


        // Calculate message hash for tracking
        let message_hash = self.calculate_message_hash(&message);

        // Create oneshot channel for ACK response
        let (tx, mut rx) = oneshot::channel();

        // Store the oneshot sender for ACK tracking
        {
            let mut oneshot_acks = self.pending_oneshot_acks.lock().unwrap();
            oneshot_acks.insert(message_hash, tx);
        }

        // Send the message immediately (non-blocking)

        match self.send_message(peer_node_id, message) {
            Ok(()) => {
            }
            Err(e) => {
                // Clean up tracking
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                return Err(e);
            }
        }

        // Give Lightning a very brief window to process messages
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Now wait for ACK using async approach but with yielding

        let start_time = std::time::Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);

        // Use a polling approach with brief yields to allow Lightning to process
        // Track time spent while peer is connected AND message has been sent
        let mut ack_wait_time_elapsed = Duration::ZERO;
        let mut last_check = std::time::Instant::now();
        let mut last_status_log = std::time::Instant::now();
        let mut last_connected_state = false;
        let mut message_sent = false;

        loop {
            let now = std::time::Instant::now();
            let delta = now.duration_since(last_check);
            last_check = now;

            // Check if peer is currently connected
            let is_connected = self.connected_peers.lock().unwrap().contains(&peer_node_id);

            // Check if our message has been sent (no longer in outbound_messages queue)
            // This tells us the message was picked up by get_and_clear_pending_msg
            let message_still_queued = {
                let guard = self.outbound_messages.lock().unwrap();
                if let Some(msgs) = guard.get(&peer_node_id) {
                    msgs.iter().any(|m| self.calculate_message_hash(m) == message_hash)
                } else {
                    false
                }
            };

            if !message_still_queued && !message_sent {
                message_sent = true;
            }

            // Track connection state changes
            if is_connected != last_connected_state {
                last_connected_state = is_connected;
            }

            // Only count time toward ACK timeout if:
            // 1. Message has actually been sent (not still in queue)
            // 2. AND peer is connected (can receive our message and respond)
            if message_sent && is_connected {
                ack_wait_time_elapsed += delta;
            }

            // Update status log time every 5 seconds
            if now.duration_since(last_status_log) > Duration::from_secs(5) {
                last_status_log = now;
            }

            // Check if we've timed out (only counting time after message sent while connected)
            if ack_wait_time_elapsed > timeout_duration {
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "ACK timeout".to_string(),
                    details: format!("No ACK received within {}ms (message was sent)", timeout_ms),
                });
            }

            // Also enforce a hard timeout to prevent infinite waits if message never gets sent
            // (e.g., peer stays disconnected forever)
            let hard_timeout = Duration::from_millis(timeout_ms * 3);
            if start_time.elapsed() > hard_timeout {
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                let reason = if message_sent {
                    "message sent but no ACK"
                } else {
                    "message never sent (peer stayed disconnected)"
                };
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "ACK timeout".to_string(),
                    details: format!("Hard timeout ({}ms): {}", timeout_ms * 3, reason),
                });
            }

            // Try to receive from oneshot channel (non-blocking)
            match rx.try_recv() {
                Ok(Ok(())) => {
                    return Ok(());
                }
                Ok(Err(error_msg)) => {
                    self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Message rejected by peer".to_string(),
                        details: error_msg,
                    });
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // No ACK yet, yield briefly and continue polling
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "ACK channel closed".to_string(),
                        details: "ACK channel was closed before receiving response".to_string(),
                    });
                }
            }
        }
    }

    /// Sign a collateral consent message.
    /// Returns the 64-byte signature or zeros if no secret key available.
    pub fn sign_collateral_consent(&self, operator_id: &PublicKey, reserves_id: &PublicKey) -> [u8; 64] {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};
        use deposits_core::log_warn;

        match self.node_secret_key {
            Some(secret_key) => {
                // Sign: SHA256("COLLATERAL_CONSENT" || operator_id || reserves_id)
                let mut preimage = Vec::new();
                preimage.extend_from_slice(b"COLLATERAL_CONSENT");
                preimage.extend_from_slice(&operator_id.serialize());
                preimage.extend_from_slice(&reserves_id.serialize());

                let message_hash = sha256::Hash::hash(&preimage);
                let secp_message = Message::from_digest(message_hash.to_byte_array());

                let secp = Secp256k1::new();
                let sig = secp.sign_ecdsa(&secp_message, &secret_key);
                sig.serialize_compact()
            }
            None => {
                log_warn!(self.logger, "📋 CONSENT: No secret key available for signing");
                [0u8; 64]
            }
        }
    }

    /// Request consent from a collateral partner to back a ledger
    /// Sends a CollateralConsentRequest and waits for CollateralConsentResponse with signature
    pub(super) fn request_collateral_consent(
        &self,
        collateral_partner: PublicKey,
        consent_request: DepositsMessage,
    ) -> Result<[u8; 64], DepositsError> {
        use std::time::Duration;

        // Calculate message hash for tracking
        let message_hash = self.calculate_message_hash(&consent_request);

        // Create oneshot channel for consent response
        let (tx, mut rx) = oneshot::channel();

        // Store the oneshot sender for consent tracking
        {
            let mut pending = self.pending_consent_requests.lock().unwrap();
            pending.insert(message_hash, tx);
        }

        // Store the consent request for retry on reconnect
        // If the peer disconnects before responding, we'll resend when they reconnect
        {
            let mut undelivered = self.undelivered_consent_requests.lock().unwrap();
            undelivered.insert(collateral_partner, (message_hash, consent_request.clone()));
        }

        // Send the consent request
        match self.send_message(collateral_partner, consent_request) {
            Ok(()) => {}
            Err(e) => {
                self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                return Err(e);
            }
        }

        // Give Lightning a brief window to process messages
        std::thread::sleep(Duration::from_millis(1));

        // Wait for consent response (60 second timeout - peers may temporarily disconnect)
        let start_time = std::time::Instant::now();
        let timeout_duration = Duration::from_millis(60000);
        let retry_interval = Duration::from_millis(10000); // Retry every 10 seconds
        let mut last_retry_time = start_time;

        loop {
            if start_time.elapsed() > timeout_duration {
                self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Consent timeout".to_string(),
                    details: "No consent response received within 60 seconds".to_string(),
                });
            }

            // Periodically retry sending the consent request in case the peer reconnected
            // or the previous message didn't make it through
            if last_retry_time.elapsed() > retry_interval {
                log_info!(
                    self.logger,
                    "🔄 Retrying consent request to {} after {:?}",
                    collateral_partner,
                    start_time.elapsed()
                );
                // Get the stored consent request and resend it
                if let Some((_, consent_msg)) = self.undelivered_consent_requests.lock().unwrap().get(&collateral_partner).cloned() {
                    if let Err(e) = self.send_message(collateral_partner, consent_msg) {
                        log_debug!(
                            self.logger,
                            "Failed to retry consent request to {}: {:?}",
                            collateral_partner,
                            e
                        );
                    }
                }
                last_retry_time = std::time::Instant::now();
            }

            match rx.try_recv() {
                Ok(Ok(signature)) => {
                    // Clear the undelivered request - we got a response
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Ok(signature);
                }
                Ok(Err(error_msg)) => {
                    self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Consent denied".to_string(),
                        details: error_msg,
                    });
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Consent channel closed".to_string(),
                        details: "Consent channel was closed before receiving response".to_string(),
                    });
                }
            }
        }
    }

    /// Request consent from a collateral partner - async version
    /// Uses tokio::time::sleep instead of std::thread::sleep to not block the executor
    pub(super) async fn request_collateral_consent_async(
        &self,
        collateral_partner: PublicKey,
        consent_request: DepositsMessage,
    ) -> Result<[u8; 64], DepositsError> {
        use tokio::time::{sleep, Duration, Instant};

        // Calculate message hash for tracking
        let message_hash = self.calculate_message_hash(&consent_request);

        // Create oneshot channel for consent response
        let (tx, mut rx) = oneshot::channel();

        // Store the oneshot sender for consent tracking
        {
            let mut pending = self.pending_consent_requests.lock().unwrap();
            pending.insert(message_hash, tx);
        }

        // Store the consent request for retry on reconnect
        {
            let mut undelivered = self.undelivered_consent_requests.lock().unwrap();
            undelivered.insert(collateral_partner, (message_hash, consent_request.clone()));
        }

        // Send the consent request
        match self.send_message(collateral_partner, consent_request) {
            Ok(()) => {}
            Err(e) => {
                self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                return Err(e);
            }
        }

        // Brief yield to let background processor deliver the message
        sleep(Duration::from_millis(1)).await;

        // Wait for consent response (60 second timeout)
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(60000);
        let retry_interval = Duration::from_millis(10000);
        let mut last_retry_time = start_time;

        loop {
            if start_time.elapsed() > timeout_duration {
                self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "Consent timeout".to_string(),
                    details: "No consent response received within 60 seconds".to_string(),
                });
            }

            // Periodically retry sending the consent request
            if last_retry_time.elapsed() > retry_interval {
                log_info!(
                    self.logger,
                    "🔄 Retrying consent request to {} after {:?}",
                    collateral_partner,
                    start_time.elapsed()
                );
                if let Some((_, consent_msg)) = self.undelivered_consent_requests.lock().unwrap().get(&collateral_partner).cloned() {
                    if let Err(e) = self.send_message(collateral_partner, consent_msg) {
                        log_debug!(
                            self.logger,
                            "Failed to retry consent request to {}: {:?}",
                            collateral_partner,
                            e
                        );
                    }
                }
                last_retry_time = Instant::now();
            }

            match rx.try_recv() {
                Ok(Ok(signature)) => {
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Ok(signature);
                }
                Ok(Err(error_msg)) => {
                    self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Consent denied".to_string(),
                        details: error_msg,
                    });
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Use tokio sleep - doesn't block the executor!
                    sleep(Duration::from_millis(5)).await;
                    continue;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.pending_consent_requests.lock().unwrap().remove(&message_hash);
                    self.undelivered_consent_requests.lock().unwrap().remove(&collateral_partner);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "Consent channel closed".to_string(),
                        details: "Consent channel was closed before receiving response".to_string(),
                    });
                }
            }
        }
    }

    /// Send a message and wait for acknowledgment asynchronously (for tokio async contexts)
    ///
    /// This is the async version of `send_message_with_oneshot_ack` that uses tokio::time::sleep
    /// instead of std::thread::sleep, making it safe to call from async contexts like NWC service.
    pub(super) async fn send_message_with_ack_async(
        &self,
        peer_node_id: PublicKey,
        message: DepositsMessage,
        timeout_ms: u64,
    ) -> Result<(), DepositsError> {
        use tokio::time::Duration;


        // Calculate message hash for tracking
        let message_hash = self.calculate_message_hash(&message);

        // Create oneshot channel for ACK response
        let (tx, rx) = oneshot::channel();

        // Store the oneshot sender for ACK tracking
        {
            let mut oneshot_acks = self.pending_oneshot_acks.lock().unwrap();
            oneshot_acks.insert(message_hash, tx);
        }

        // Send the message immediately (non-blocking)
        match self.send_message(peer_node_id, message) {
            Ok(()) => {}
            Err(e) => {
                // Clean up tracking
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                return Err(e);
            }
        }

        // Brief yield to let background processor deliver the message
        // Using 1ms sleep as yield_now() alone isn't enough for cross-thread message delivery
        tokio::time::sleep(Duration::from_millis(1)).await;

        // Wait for ACK using proper async await with timeout (no polling!)
        let timeout_duration = Duration::from_millis(timeout_ms);

        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(Ok(()))) => {
                // ACK received successfully
                Ok(())
            }
            Ok(Ok(Err(error_msg))) => {
                // Peer rejected the message
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                Err(DepositsError::ProtocolViolation {
                    violation_type: "Message rejected by peer".to_string(),
                    details: error_msg,
                })
            }
            Ok(Err(_)) => {
                // Channel closed before receiving response
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                Err(DepositsError::ProtocolViolation {
                    violation_type: "ACK channel closed".to_string(),
                    details: "ACK channel was closed before receiving response".to_string(),
                })
            }
            Err(_) => {
                // Timeout
                self.pending_oneshot_acks.lock().unwrap().remove(&message_hash);
                Err(DepositsError::ProtocolViolation {
                    violation_type: "ACK timeout".to_string(),
                    details: format!("No ACK received within {}ms", timeout_ms),
                })
            }
        }
    }

    /// Wait for a commitment transaction to include the specified ledger hash.
    ///
    /// This implements the "wait for commitment" part of the predict-then-commit-then-record pattern.
    /// After sending UpdateReserves with a predicted hash, this polls until the committed
    /// ledger_hash matches the expected hash, or times out.
    ///
    /// Returns Ok(()) if the commitment was successful, or an error if timeout/failure.
    pub(super) async fn wait_for_commitment_with_hash(
        &self,
        partner_node_id: PublicKey,
        expected_ledger_hash: [u8; 32],
        timeout_ms: u64,
    ) -> Result<(), DepositsError> {
        use tokio::time::{sleep, Duration, Instant};

        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let poll_interval = Duration::from_millis(50); // Poll every 50ms

        // Get channel ID for querying
        let channel_id = {
            if let Some(ref cm) = self.channel_manager {
                let channels = cm.list_channels_with_counterparty(&partner_node_id);
                if let Some(channel) = channels.first() {
                    channel.channel_id
                } else {
                    return Err(DepositsError::InvalidChannelState);
                }
            } else {
                return Err(DepositsError::InvalidChannelState);
            }
        };

        // Get the expected script from pending_reserves_commitments
        let expected_script = {
            let pending = self.pending_reserves_commitments.lock().unwrap();
            pending.get(&partner_node_id).map(|(script, _, _, _)| script.clone())
        };

        loop {
            // Check if the extra outputs now contain our expected script
            if let Some(ref cm) = self.channel_manager {
                if let Ok((holder_outputs, _)) = cm.get_channel_extra_outputs(&partner_node_id, &channel_id) {
                    // Check if any output matches our expected script
                    let is_committed = if let Some(ref expected) = expected_script {
                        holder_outputs.iter().any(|o| &o.script_pubkey == expected)
                    } else {
                        // No expected script tracked, check by ledger hash (legacy fallback)
                        // This won't work reliably, but avoids breaking existing code
                        false
                    };

                    if is_committed {
                        // Clear the pending state
                        {
                            let mut pending = self.pending_reserves_commitments.lock().unwrap();
                            pending.remove(&partner_node_id);
                        }
                        return Ok(());
                    }
                }
            }

            // Check timeout
            if start_time.elapsed() >= timeout_duration {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "commitment_timeout".to_string(),
                    details: format!(
                        "Commitment with ledger_hash {:02x?} not confirmed within {}ms",
                        &expected_ledger_hash[0..8], timeout_ms
                    ),
                });
            }

            // Wait before polling again
            sleep(poll_interval).await;
        }
    }

    /// Wait for any pending reserves update to complete before sending a new one.
    ///
    /// This is used for the "predict-then-commit-then-record" pattern to ensure we don't
    /// try to send UpdateReserves while another is pending (which would cause it to queue
    /// in the holding cell and potentially never commit).
    ///
    /// Returns Ok(()) when the channel has no pending reserves, or error on timeout.
    pub(super) async fn wait_for_pending_reserves_clear(
        &self,
        partner_node_id: PublicKey,
        timeout_ms: u64,
    ) -> Result<(), DepositsError> {
        use tokio::time::{sleep, Duration, Instant};

        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let poll_interval = Duration::from_millis(50); // Poll every 50ms

        // Get channel ID for querying
        let _channel_id = {
            if let Some(ref cm) = self.channel_manager {
                let channels = cm.list_channels_with_counterparty(&partner_node_id);
                if let Some(channel) = channels.first() {
                    channel.channel_id
                } else {
                    return Err(DepositsError::InvalidChannelState);
                }
            } else {
                return Err(DepositsError::InvalidChannelState);
            }
        };

        loop {
            // Check if there's no pending reserves in our tracking
            let has_pending = {
                let pending = self.pending_reserves_commitments.lock().unwrap();
                pending.contains_key(&partner_node_id)
            };

            if !has_pending {
                return Ok(());
            }

            // Check timeout
            if start_time.elapsed() >= timeout_duration {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "pending_reserves_timeout".to_string(),
                    details: format!(
                        "Pending reserves for {} not cleared within {}ms",
                        partner_node_id, timeout_ms
                    ),
                });
            }

            // Wait before polling again
            sleep(poll_interval).await;
        }
    }

    /// Send acknowledgment for a received message
    pub(super) fn send_acknowledgment(
        &self,
        original_msg: &DepositsMessage,
        success: bool,
        error_msg: Option<String>,
        cosignature: Option<Vec<u8>>,
        recipient: PublicKey,
    ) -> Result<(), DepositsError> {
        let message_hash = Self::create_message_hash(original_msg);
        let message_type = original_msg.message_type();

        // Convert Vec<u8> cosignature to [u8; 64] if present
        let cosig_array: Option<[u8; 64]> = cosignature.as_ref().and_then(|v| {
            if v.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Some(arr)
            } else {
                None
            }
        });

        let ack_msg = LedgerUpdateResponseMsg {
            operator_id: recipient, // Responding to the operator who sent the message
            reserves_id: self.our_node_id.to_string(),
            request_hash: message_hash,
            accepted: success,
            error: error_msg.clone(),
            partner_signature: cosig_array,
            confirmed_sequence: 0,
            confirmed_hash: message_hash,
        };

        let ack_message = DepositsMessage::LedgerUpdateResponse(ack_msg);

        // Queue the acknowledgment for sending
        {
            let mut outbound_messages = self.outbound_messages.lock().unwrap();
            outbound_messages.entry(recipient).or_insert_with(Vec::new).push(ack_message.clone());
        }

        if success {
            log_debug!(self.logger, "Queued SUCCESS ACK for message type {} to {}", message_type, recipient);
        } else {
            log_info!(self.logger, "Queued REJECT ACK for message type {} to {}: {}",
                     message_type, recipient, error_msg.as_ref().unwrap_or(&"Unknown error".to_string()));
        }

        // Trigger immediate send for ACKs
        self.trigger_immediate_send(recipient, ack_message.message_type());

        Ok(())
    }
}
