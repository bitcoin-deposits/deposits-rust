// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signed update operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for creating, verifying, and persisting
//! signed ledger updates as part of the audit trail, extracted from core.rs.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, SyncMsg};
use super::ledger_ext::{SignedLedgerUpdateExt, SignedLedgerUpdateLogExt};
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Create a signed ledger update for audit trail
    ///
    /// This creates a cryptographically signed record of a ledger operation that can be
    /// independently verified by auditors. The signature covers the message, sequence number,
    /// hash chain, and optionally the partner's signature (porcupine dance).
    ///
    /// # Arguments
    /// * `message` - The ledger operation message
    /// * `partner_id` - The channel partner's node ID
    /// * `sequence_number` - The update's sequence in the ledger
    /// * `previous_hash` - Hash of the previous ledger state
    /// * `current_hash` - Hash after applying this update
    /// * `partner_signature` - Optional partner signature from ACK (enables full porcupine signing)
    ///
    /// # Signature Format
    /// - With partner signature: message || msg_type || seq || prev || curr || timestamp || partner_sig
    /// - Without partner signature: message || seq || prev (basic format for backwards compatibility)
    pub(super) fn create_signed_update(
        &self,
        message: &DepositsMessage,
        partner_id: PublicKey,
        sequence_number: u64,
        previous_hash: [u8; 32],
        current_hash: [u8; 32],
        partner_signature: Option<[u8; 64]>,
    ) -> Result<deposits_core::SignedLedgerUpdate, DepositsError> {
        use deposits_core::SignedLedgerUpdate;
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::Secp256k1;

        // 1. Serialize the message using Lightning's wire protocol
        // IMPORTANT: Use write() which skips the type prefix, NOT encode() which includes it.
        // The message_type is stored separately in SignedLedgerUpdate.message_type.
        // This must match what append does in ledger.rs.
        use lightning::util::ser::Writeable;
        let mut message_bytes = Vec::new();
        message.write(&mut message_bytes).expect("Message encoding should never fail");

        // 2. Get message type
        let message_type = message.message_type();

        // 3. Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| DepositsError::InvalidState("System time error".to_string()))?
            .as_secs();

        // 4. Determine partner signature and create final operator signature
        let partner_sig = partner_signature.unwrap_or([0u8; 64]);

        // 5. Create operator signature
        // If partner signature is provided, sign the full operator_signing_data (which includes partner sig)
        // Otherwise, sign the basic data for backwards compatibility
        let operator_signature = if partner_signature.is_some() {
            // Full porcupine dance: operator signs (content || partner_signature)
            let secret_key = self.node_secret_key
                .ok_or_else(|| DepositsError::InvalidState(
                    "Node secret key not set - call set_node_secret_key()".to_string()
                ))?;

            // Build signing data: message || message_type || seq || prev_hash || curr_hash || timestamp || partner_sig
            let mut signing_data = Vec::new();
            signing_data.extend_from_slice(&message_bytes);
            signing_data.extend_from_slice(&message_type.to_be_bytes());
            signing_data.extend_from_slice(&sequence_number.to_be_bytes());
            signing_data.extend_from_slice(&previous_hash);
            signing_data.extend_from_slice(&current_hash);
            signing_data.extend_from_slice(&timestamp.to_be_bytes());
            signing_data.extend_from_slice(&partner_sig);

            let message_hash = sha256::Hash::hash(&signing_data);
            let secp = Secp256k1::signing_only();
            let sig = secp.sign_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array()),
                &secret_key,
            );

            println!("🔏 PORCUPINE: Created final operator signature covering partner signature");
            sig.serialize_compact()
        } else {
            // Fallback: basic signature for backwards compatibility
            self.sign_ledger_update(
                &message_bytes,
                sequence_number,
                &previous_hash,
            )?
        };

        // 6. Create signed update
        Ok(SignedLedgerUpdate {
            message: message_bytes,
            message_type,
            operator_signature,
            partner_signature: partner_sig,
            operator_id: self.our_node_id,
            partner_id: partner_id,
            sequence_number,
            previous_hash,
            current_hash,
            timestamp,
        })
    }

    /// Sign ledger update data with operator's Lightning node key
    ///
    /// Signs: message_bytes || sequence_number || previous_hash
    pub(super) fn sign_ledger_update(
        &self,
        message_bytes: &[u8],
        sequence_number: u64,
        previous_hash: &[u8; 32],
    ) -> Result<[u8; 64], DepositsError> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::Secp256k1;

        // Get node secret key
        let secret_key = self.node_secret_key
            .ok_or_else(|| DepositsError::InvalidState(
                "Node secret key not set - call set_node_secret_key()".to_string()
            ))?;

        // Create signing data: message || sequence || prev_hash
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(message_bytes);
        signing_data.extend_from_slice(&sequence_number.to_be_bytes());
        signing_data.extend_from_slice(previous_hash);

        // Hash the signing data
        let message_hash = sha256::Hash::hash(&signing_data);

        // Sign with ECDSA
        let secp = Secp256k1::signing_only();
        let signature = secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &secret_key,
        );

        Ok(signature.serialize_compact())
    }

    /// Verify a signed ledger update's ECDSA signature
    ///
    /// This is called by auditors when receiving signed updates from operators.
    /// Verifies that the signature is valid for the given message, sequence, and previous hash.
    ///
    /// The signing format depends on whether porcupine signing was used:
    /// - With partner signature: message || msg_type || seq || prev || curr || timestamp || partner_sig
    /// - Without partner signature: message || seq || prev (basic format)
    pub(super) fn verify_signed_update(
        update: &deposits_core::SignedLedgerUpdate
    ) -> Result<(), DepositsError> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};
        use bitcoin::secp256k1::ecdsa::Signature;

        // 1. Recreate the signing data - format depends on whether porcupine signing was used
        let signing_data = if update.partner_signature != [0u8; 64] {
            // Porcupine format: message || msg_type || seq || prev || curr || timestamp || partner_sig
            let mut data = Vec::new();
            data.extend_from_slice(&update.message);
            data.extend_from_slice(&update.message_type.to_be_bytes());
            data.extend_from_slice(&update.sequence_number.to_be_bytes());
            data.extend_from_slice(&update.previous_hash);
            data.extend_from_slice(&update.current_hash);
            data.extend_from_slice(&update.timestamp.to_be_bytes());
            data.extend_from_slice(&update.partner_signature);
            data
        } else {
            // Basic format: use extension trait method
            <deposits_core::SignedLedgerUpdateLog as SignedLedgerUpdateLogExt>::create_signing_data(update)
        };

        // 2. Hash the signing data
        let message_hash = sha256::Hash::hash(&signing_data);

        // 3. Parse the signature
        let signature = Signature::from_compact(&update.operator_signature)
            .map_err(|_| DepositsError::InvalidState(
                "Invalid signature format".to_string()
            ))?;

        // 4. Verify the signature
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(
            &Message::from_digest(message_hash.to_byte_array()),
            &signature,
            &update.operator_id,
        ).map_err(|_| DepositsError::InvalidState(
            "Signature verification failed".to_string()
        ))?;

        Ok(())
    }

    /// Verify and store a signed update received as an auditor
    ///
    /// This is called when an auditor receives a signed ledger update from an operator.
    /// It verifies the signature and stores it in the local audit trail.
    pub(super) fn verify_and_store_signed_update(
        &self,
        signed_update: deposits_core::SignedLedgerUpdate,
    ) -> Result<(), DepositsError> {
        // Skip if we're the operator (we created this update, already have it)
        if signed_update.operator_id == self.our_node_id {
            log_debug!(
                self.logger,
                "📋 AUDIT: Skipping signed update - we are the operator (already have this update)",
            );
            return Ok(());
        }

        // If we're the partner, we SHOULD receive and store this update.
        // Partners no longer maintain their own hash chain - they receive authoritative
        // SignedAuditUpdate from operator. This prevents hash divergence.
        let we_are_partner = signed_update.partner_id == self.our_node_id;
        if we_are_partner {
            log_info!(
                self.logger,
                "📋 PARTNER: Receiving authoritative SignedAuditUpdate seq={} from operator {} for our partner ledger",
                signed_update.sequence_number,
                signed_update.operator_id
            );
        }

        // 1. Verify the ECDSA signature
        Self::verify_signed_update(&signed_update)?;

        log_debug!(
            self.logger,
            "✅ Verified signature for update seq={} from operator {} -> partner {}",
            signed_update.sequence_number,
            signed_update.operator_id,
            signed_update.partner_id
        );

        // 2. Add to local log (verifies sequence/hash chain)
        let mut logs = self.signed_update_logs.lock().unwrap();

        let log = logs.entry((signed_update.operator_id, signed_update.partner_id))
            .or_insert_with(|| {
                deposits_core::SignedLedgerUpdateLog::new(
                    signed_update.operator_id,
                    signed_update.partner_id
                )
            });

        log.add_update(signed_update.clone())
            .map_err(|e| {
                log_error!(
                    self.logger,
                    "Failed to add signed update seq={} to audit log: {}",
                    signed_update.sequence_number,
                    e
                );
                DepositsError::InvalidState(format!("Failed to add update: {}", e))
            })?;

        drop(logs); // Release lock before persisting

        // 3. Persist to disk
        self.persist_signed_update(
            signed_update.operator_id,
            signed_update.partner_id,
            signed_update.clone()
        )?;

        Ok(())
    }

    /// Persist a signed ledger update to storage
    ///
    /// NOTE: This function expects the update to ALREADY be in the in-memory log.
    /// It just persists the current state of the log to disk.
    pub(super) fn persist_signed_update(
        &self,
        operator_id: PublicKey,
        partner_id: PublicKey,
        _signed_update: deposits_core::SignedLedgerUpdate,
    ) -> Result<(), DepositsError> {
        // Get the existing log (should already contain the update from verify_and_store)
        let logs = self.signed_update_logs.lock().unwrap();
        let log = logs.get(&(operator_id, partner_id))
            .ok_or_else(|| DepositsError::InvalidState(
                "Attempted to persist update for non-existent log".to_string()
            ))?;

        // Persist to disk using hashed key (same as ledger persistence)
        // Key format: signed_updates_{hash} where hash = SHA256(operator_id || partner_id)
        use bitcoin::hashes::{Hash, sha256};
        let mut key_input = Vec::new();
        key_input.extend_from_slice(&operator_id.serialize());
        key_input.extend_from_slice(&partner_id.serialize());
        let key_hash = sha256::Hash::hash(&key_input);
        let key = format!("signed_updates_{}", hex::encode(key_hash.as_byte_array()));

        let serialized = bincode::serialize(log)
            .map_err(|_| DepositsError::SerializationError)?;

        self.kv_store.write("deposits", "signed_ledger_updates", &key, serialized)
            .map_err(|e| {
                log_error!(
                    self.logger,
                    "Failed to persist signed update for ledger (op={}, partner={}): {}",
                    operator_id,
                    partner_id,
                    e
                );
                DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        log_debug!(
            self.logger,
            "🔏 Persisted signed update seq={} for ledger (op={}, partner={})",
            log.next_sequence.saturating_sub(1),
            operator_id,
            partner_id
        );

        Ok(())
    }

    /// Load signed ledger update log from storage
    pub(super) fn load_signed_update_log(
        &self,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) -> Result<deposits_core::SignedLedgerUpdateLog, DepositsError> {
        // Use hashed key (same as persist_signed_update)
        use bitcoin::hashes::{Hash, sha256};
        let mut key_input = Vec::new();
        key_input.extend_from_slice(&operator_id.serialize());
        key_input.extend_from_slice(&partner_id.serialize());
        let key_hash = sha256::Hash::hash(&key_input);
        let key = format!("signed_updates_{}", hex::encode(key_hash.as_byte_array()));

        match self.kv_store.read("deposits", "signed_ledger_updates", &key) {
            Ok(data) => {
                bincode::deserialize(&data)
                    .map_err(|_| DepositsError::InvalidState(
                        "Failed to deserialize signed update log".to_string()
                    ))
            }
            Err(_) => {
                // No existing log, create new one
                Ok(deposits_core::SignedLedgerUpdateLog::new(operator_id, partner_id))
            }
        }
    }

    /// Handle audit sync request from another auditor
    ///
    /// When an auditor requests missing updates, we send them all updates after their last known sequence
    pub(super) fn handle_audit_sync_request(
        &self,
        request: &SyncMsg,
        requester: PublicKey,
    ) -> Result<(), DepositsError> {
        log_info!(
            self.logger,
            "📋 SYNC: Received audit sync request from {} for operator {} -> partner {} (after seq={})",
            requester,
            request.operator_id,
            request.partner_id,
            request.last_known_sequence
        );

        // Load our stored signed updates for this ledger
        let logs = self.signed_update_logs.lock().unwrap();
        let updates_to_send = if let Some(log) = logs.get(&(request.operator_id, request.partner_id)) {
            // Get updates since the requested sequence
            let updates = log.get_updates_since(request.last_known_sequence);

            log_info!(
                self.logger,
                "📋 SYNC: Found {} updates to send to {}",
                updates.len(),
                requester
            );

            updates
        } else {
            log_debug!(
                self.logger,
                "📋 SYNC: No signed updates found for operator {} -> partner {}",
                request.operator_id,
                request.partner_id
            );
            Vec::new()
        };

        drop(logs); // Release lock before sending

        // Send response - SignedLedgerUpdate is the same as StorageSignedLedgerUpdate
        use super::messages::{SyncResponseMsg, DepositsMessage};
        let current_sequence = updates_to_send.last().map(|u| u.sequence_number).unwrap_or(0);
        let current_hash = updates_to_send.last().map(|u| u.current_hash).unwrap_or([0u8; 32]);
        let response = DepositsMessage::SyncResponse(SyncResponseMsg {
            operator_id: request.operator_id,
            partner_id: request.partner_id,
            request_hash: [0u8; 32], // Not tracking request hashes for audit sync
            updates: updates_to_send.clone(),
            current_sequence,
            current_hash,
        });

        self.send_message(requester, response)?;

        log_info!(
            self.logger,
            "📋 SYNC: Sent {} updates to {}",
            updates_to_send.len(),
            requester
        );

        Ok(())
    }

    /// Handle audit sync response from another auditor
    ///
    /// When we receive missing updates from another auditor, verify and store them
    pub(super) fn handle_audit_sync_response(
        &self,
        response: &deposits_core::messages::SyncResponseMsg,
        sender: PublicKey,
    ) -> Result<(), DepositsError> {
        log_info!(
            self.logger,
            "📋 SYNC: Received {} updates from {} for operator {} -> partner {}",
            response.updates.len(),
            sender,
            response.operator_id,
            response.partner_id
        );

        let mut stored_count = 0;
        let mut failed_count = 0;

        // Process each update - updates are already in storage format (bytes are bytes)
        for signed_update in &response.updates {
            // Verify and store (clone since we're iterating by reference)
            match self.verify_and_store_signed_update(signed_update.clone()) {
                Ok(()) => {
                    stored_count += 1;
                    log_debug!(
                        self.logger,
                        "📋 SYNC: Successfully stored update seq={}",
                        signed_update.sequence_number
                    );
                }
                Err(e) => {
                    failed_count += 1;
                    log_error!(
                        self.logger,
                        "📋 SYNC: Failed to store update seq={}: {}",
                        signed_update.sequence_number,
                        e
                    );
                }
            }
        }

        log_info!(
            self.logger,
            "📋 SYNC: Processed {} updates: {} stored, {} failed",
            response.updates.len(),
            stored_count,
            failed_count
        );

        if failed_count > 0 {
            Err(DepositsError::InvalidState(
                format!("Failed to store {} updates", failed_count)
            ))
        } else {
            Ok(())
        }
    }

    /// Sign ledger update content as partner (for porcupine dance)
    ///
    /// Partner signs CONTENT ONLY (not operator signature) to prevent being
    /// tricked into endorsing an invalid state. The operator will create a
    /// final signature covering the partner's signature.
    ///
    /// Signs: message || message_type || sequence || prev_hash || curr_hash || timestamp
    pub(super) fn sign_as_partner(
        &self,
        message_bytes: &[u8],
        message_type: u16,
        sequence_number: u64,
        previous_hash: &[u8; 32],
        current_hash: &[u8; 32],
        timestamp: u64,
    ) -> Result<[u8; 64], DepositsError> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::Secp256k1;

        // Get node secret key
        let secret_key = self.node_secret_key
            .ok_or_else(|| DepositsError::InvalidState(
                "Node secret key not set - call set_node_secret_key()".to_string()
            ))?;

        // Create partner signing data: matches SignedLedgerUpdate::partner_signing_data()
        // Partner signs content only - NOT the operator signature
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(message_bytes);
        signing_data.extend_from_slice(&message_type.to_be_bytes());
        signing_data.extend_from_slice(&sequence_number.to_be_bytes());
        signing_data.extend_from_slice(previous_hash);
        signing_data.extend_from_slice(current_hash);
        signing_data.extend_from_slice(&timestamp.to_be_bytes());

        // Hash the signing data
        let message_hash = sha256::Hash::hash(&signing_data);

        // Sign with ECDSA
        let secp = Secp256k1::signing_only();
        let signature = secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array()),
            &secret_key,
        );

        Ok(signature.serialize_compact())
    }

    /// Sign attestation content (for CollateralAttestation)
    ///
    /// Signs the provided content bytes using Schnorr signature
    pub(super) fn sign_attestation_content(&self, content: &[u8]) -> Result<[u8; 64], DepositsError> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::Secp256k1;

        // Get node secret key
        let secret_key = self.node_secret_key
            .ok_or_else(|| DepositsError::InvalidState(
                "Node secret key not set - call set_node_secret_key()".to_string()
            ))?;

        // Hash the content
        let content_hash = sha256::Hash::hash(content);

        // Sign with Schnorr
        let secp = Secp256k1::new();
        let keypair = secret_key.keypair(&secp);
        let message = bitcoin::secp256k1::Message::from_digest(content_hash.to_byte_array());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        Ok(*signature.as_ref())
    }

    /// Send the full audit history to a newly added collateral partner
    ///
    /// This is called after add_collateral_partner adds the collateral partner to the quorum.
    /// The ACK handler's broadcast_message_to_other_partners ran BEFORE the collateral partner
    /// was in the quorum, so they didn't receive ANY updates.
    /// We need to send them the ENTIRE hash chain from sequence 0 so they can verify it.
    pub(super) fn send_audit_update_to_new_collateral_partner(
        &self,
        partner_node_id: PublicKey,
        collateral_partner: PublicKey,
        _message: &DepositsMessage,  // Not used anymore - we send all updates
    ) -> Result<(), DepositsError> {
        use super::messages::LedgerUpdateMsg;

        log_info!(
            self.logger,
            "📋 Sending full audit history to new collateral partner {} for ledger ({}, {})",
            collateral_partner,
            self.our_node_id,
            partner_node_id
        );

        // Get all updates from the ledger
        let updates_to_send: Vec<_> = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();

                if ledger.history.is_empty() {
                    log_warn!(
                        self.logger,
                        "No updates in ledger to send to collateral partner"
                    );
                    return Ok(());
                }

                // Collect all updates with their hashes
                // For each update, we need: message, sequence_number, previous_hash, current_hash
                let mut result = Vec::new();
                for (i, update) in ledger.history.iter().enumerate() {
                    let current_hash = update.current_hash;

                    // Deserialize the message using SignedLedgerUpdateExt trait
                    // This correctly uses the separate message_type field instead of
                    // trying to decode a type prefix from the message bytes
                    let msg = match update.get_message() {
                        Ok(m) => m,
                        Err(e) => {
                            log_warn!(
                                self.logger,
                                "Failed to deserialize update {} for audit history: {:?}",
                                i, e
                            );
                            continue;
                        }
                    };

                    result.push((msg, update.sequence_number, update.previous_hash, current_hash));
                }
                result
            } else {
                log_warn!(
                    self.logger,
                    "Ledger not found when sending audit history to collateral partner"
                );
                return Ok(());
            }
        };

        // Debug: Print the actual sequence numbers being sent
        let seqs: Vec<u64> = updates_to_send.iter().map(|(_, seq, _, _)| *seq).collect();
        println!(
            "🟢 Sending {} SignedAuditUpdates to new collateral partner {} (seqs: {:?})",
            updates_to_send.len(),
            collateral_partner,
            seqs
        );

        log_info!(
            self.logger,
            "📋 Sending {} updates to new collateral partner {}",
            updates_to_send.len(),
            collateral_partner
        );

        // Create signed updates and send as a SyncResponse bundle
        let mut signed_updates = Vec::new();
        for (msg, sequence_number, prev_hash, current_hash) in updates_to_send {
            // Create the signed update (resync path - no fresh partner signature)
            let signed_update = match self.create_signed_update(
                &msg,
                partner_node_id,
                sequence_number,
                prev_hash,
                current_hash,
                None, // Resync path - historical updates, no partner signature
            ) {
                Ok(update) => update,
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "Failed to create signed update seq={} for audit history: {:?}",
                        sequence_number, e
                    );
                    continue;
                }
            };
            signed_updates.push(signed_update);
        }

        // Send all updates in a SyncResponse
        use super::messages::{SyncResponseMsg, DepositsMessage};
        let current_sequence = signed_updates.last().map(|u| u.sequence_number).unwrap_or(0);
        let current_hash = signed_updates.last().map(|u| u.current_hash).unwrap_or([0u8; 32]);
        let sync_response = DepositsMessage::SyncResponse(SyncResponseMsg {
            operator_id: self.our_node_id,
            partner_id: partner_node_id,
            request_hash: [0u8; 32], // Not a request-response, this is a push
            updates: signed_updates,
            current_sequence,
            current_hash,
        });

        if let Err(e) = self.send_message(collateral_partner, sync_response) {
            log_warn!(
                self.logger,
                "Failed to send audit history to collateral partner: {:?}",
                e
            );
        }

        log_info!(
            self.logger,
            "✅ Sent full audit history to new collateral partner {}",
            collateral_partner
        );

        Ok(())
    }
}
