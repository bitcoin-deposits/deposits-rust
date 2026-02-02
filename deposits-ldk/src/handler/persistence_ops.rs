// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Persistence operations for the Bitcoin Deposits protocol.
//!
//! This module contains handlers for persistence and recovery operations, extracted from core.rs
//! to improve maintainability.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use deposits_core::Ledger;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;
use std::sync::{Arc, RwLock};

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Recover persistent state on startup
    pub(super) fn recover_persistent_state(&self) -> Result<(), deposits_core::DepositsError> {
        log_info!(self.logger, "Recovering Bitcoin Deposits persistent state...");

        // Load all persisted ledgers
        let ledger_keys = self.kv_store.list("deposits", "ledgers")
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        let mut ledgers = self.ledgers.lock().unwrap();
        let mut recovered_count = 0;

        for key in ledger_keys.iter() {
            if !self.is_ledger_key(&key) {
                continue;
            }

            // Load the ledger directly from storage using the hashed key
            match self.kv_store.read("deposits", "ledgers", &key) {
                Ok(data) => {
                    match bincode::deserialize::<Ledger>(&data) {
                        Ok(ledger) => {
                            // Only recover ledgers where we are the operator OR partner
                            // (we might be the partner receiving deposits from others)
                            let our_id_str = self.our_node_id.to_string();
                            if ledger.operator_key() == self.our_node_id || ledger.reserves_key() == our_id_str {
                                let operator_id = ledger.operator_key();
                                let reserves_id = ledger.reserves_key().to_string();
                                let history_len = ledger.history.len();

                                // Removed: clear_stale_uncommitted_changes (handler concern)

                                // Store with (operator, partner) key
                                ledgers.insert((operator_id, reserves_id.clone()), Arc::new(RwLock::new(ledger)));
                                recovered_count += 1;
                                log_info!(self.logger, "Recovered ledger (operator={}, partner={}) with {} history entries", operator_id, reserves_id, history_len);
                            } else {
                            }
                        }
                        Err(_e) => {
                            return Err(DepositsError::SerializationError);
                        }
                    }
                }
                Err(_e) => {
                    // Continue with other keys
                }
            }
        }

        log_info!(self.logger, "Recovered {} Bitcoin Deposits ledgers", recovered_count);

        // Release the lock before the next phase
        drop(ledgers);

        // Load all persisted audit ledgers
        let audit_ledger_keys = self.kv_store.list("deposits", "audit_ledgers")
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        let mut ledgers = self.ledgers.lock().unwrap();
        let mut audit_recovered_count = 0;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct AuditLedgerWrapper {
            operator_id: Vec<u8>,
            reserves_id: String,
            ledger: Ledger,
        }

        for key in audit_ledger_keys.iter() {
            // Read the raw data and deserialize the wrapper to get the IDs
            match self.kv_store.read("deposits", "audit_ledgers", &key) {
                Ok(data) => {
                    match bincode::deserialize::<AuditLedgerWrapper>(&data) {
                        Ok(wrapper) => {
                            if let Ok(operator_id) = PublicKey::from_slice(&wrapper.operator_id) {
                                let reserves_id = wrapper.reserves_id;
                                ledgers.insert((operator_id, reserves_id.clone()), Arc::new(RwLock::new(wrapper.ledger)));
                                audit_recovered_count += 1;
                                log_info!(self.logger, "Recovered audit ledger for (operator={}, partner={})", operator_id, reserves_id);
                            } else {
                            }
                        }
                        Err(e) => {
                            log_error!(self.logger, "Failed to deserialize audit ledger: {}", e);
                            return Err(DepositsError::SerializationError);
                        }
                    }
                }
                Err(e) => {
                    return Err(DepositsError::PersistenceFailed { reason: e.to_string() });
                }
            }
        }

        log_info!(self.logger, "Recovered {} audit ledgers", audit_recovered_count);

        // Release the lock before signed update log recovery
        drop(ledgers);

        // Load all persisted signed update logs
        let signed_update_keys = self.kv_store.list("deposits", "signed_ledger_updates")
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        let mut signed_update_logs = self.signed_update_logs.lock().unwrap();
        let mut signed_update_recovered_count = 0;

        for key in signed_update_keys.iter() {
            // Expected key format: "signed_updates_{hash}" where hash = SHA256(operator || partner)
            if !key.starts_with("signed_updates_") {
                continue;
            }

            // Load the signed update log directly (it contains ledger_id)
            match self.kv_store.read("deposits", "signed_ledger_updates", &key) {
                Ok(data) => {
                    match bincode::deserialize::<deposits_core::SignedLedgerUpdateLog>(&data) {
                        Ok(log) => {
                            let ledger_id = log.ledger_id;
                            let update_count = log.updates.len();
                            signed_update_logs.insert(ledger_id, log);
                            signed_update_recovered_count += 1;
                            log_info!(
                                self.logger,
                                "Recovered signed update log for ledger {} with {} updates",
                                hex::encode(ledger_id),
                                update_count
                            );
                        }
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "Failed to deserialize signed update log from key {}: {}",
                                key,
                                e
                            );
                            // Continue with other logs
                        }
                    }
                }
                Err(e) => {
                    log_debug!(self.logger, "Failed to read signed update log from key {}: {}", key, e);
                    // Continue with other logs
                }
            }
        }

        log_info!(self.logger, "Recovered {} signed update logs", signed_update_recovered_count);

        // Verify the integrity of all recovered signed update logs
        log_info!(self.logger, "Verifying integrity of recovered signed update logs...");
        drop(signed_update_logs); // Release lock from recovery

        let logs = self.signed_update_logs.lock().unwrap();
        let mut verification_failures = 0;

        for (ledger_id, log) in logs.iter() {
            log_debug!(
                self.logger,
                "Verifying chain for ledger {} ({} updates)",
                hex::encode(ledger_id),
                log.updates.len()
            );

            match log.verify_chain() {
                Ok(()) => {
                    log_debug!(
                        self.logger,
                        "✓ Chain verification passed for ledger {}",
                        hex::encode(ledger_id)
                    );
                }
                Err(e) => {
                    verification_failures += 1;
                    log_error!(
                        self.logger,
                        "✗ Chain verification FAILED for ledger {}: {}",
                        hex::encode(ledger_id),
                        e
                    );
                }
            }
        }

        drop(logs); // Release lock

        if verification_failures > 0 {
            log_error!(
                self.logger,
                "Chain verification failed for {} signed update log(s)",
                verification_failures
            );
        } else {
            log_info!(
                self.logger,
                "✅ All {} signed update log chains verified successfully",
                signed_update_recovered_count
            );
        }

        // Load all persisted partner ledgers
        log_info!(self.logger, "Recovering partner ledgers...");
        let partner_ledger_keys = self.kv_store.list("deposits", "ledgers")
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        let mut ledgers = self.ledgers.lock().unwrap();
        let mut partner_recovered_count = 0;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct PartnerLedgerWrapper {
            operator_id: Vec<u8>,
            reserves_id: String,
            ledger: Ledger,
        }

        for key in partner_ledger_keys.iter() {
            // Read the raw data and deserialize the wrapper to get the IDs
            match self.kv_store.read("deposits", "ledgers", &key) {
                Ok(data) => {
                    match bincode::deserialize::<PartnerLedgerWrapper>(&data) {
                        Ok(wrapper) => {
                            if let Ok(operator_id) = PublicKey::from_slice(&wrapper.operator_id) {
                                let reserves_id = wrapper.reserves_id;
                                // Only recover if we are the partner
                                if reserves_id == self.our_node_id.to_string() {
                                    ledgers.insert((operator_id, reserves_id), Arc::new(RwLock::new(wrapper.ledger)));
                                    partner_recovered_count += 1;
                                    log_info!(self.logger, "Recovered partner ledger for operator {}", operator_id);
                                }
                            } else {
                                log_error!(self.logger, "Failed to parse operator public key from partner ledger wrapper");
                            }
                        }
                        Err(e) => {
                            log_error!(self.logger, "Failed to deserialize partner ledger: {}", e);
                            // Continue with other ledgers - don't fail entire recovery
                        }
                    }
                }
                Err(e) => {
                    log_debug!(self.logger, "Failed to read partner ledger from key {}: {}", key, e);
                    // Continue with other ledgers
                }
            }
        }

        log_info!(self.logger, "Recovered {} partner ledgers", partner_recovered_count);

        Ok(())
    }

    /// Persist a channel ledger to storage
    pub(super) fn persist_ledger_state(&self, ledger: &Ledger) -> Result<(), DepositsError> {
        // Key format: ledger_{hash} where hash = SHA256(operator_id || reserves_id)
        // This keeps the key short while still distinguishing Alice->Eve from Eve->Alice
        use bitcoin::hashes::{Hash, sha256};
        let mut key_input = Vec::new();
        key_input.extend_from_slice(&ledger.operator_key().serialize());
        key_input.extend_from_slice(ledger.reserves_key().as_bytes());
        let key_hash = sha256::Hash::hash(&key_input);
        let key = format!("ledger_{}", hex::encode(key_hash.as_byte_array()));


        // Use bincode for efficient binary serialization (like Lightning does internally)
        let serialized = bincode::serialize(ledger)
            .map_err(|e| {
                log_error!(self.logger, "Failed to serialize ledger for operator {} -> partner {}: {}",
                    ledger.operator_key(), ledger.reserves_key(), e);
                deposits_core::DepositsError::SerializationError
            })?;


        self.kv_store.write("deposits", "ledgers", &key, serialized)
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        log_debug!(self.logger, "Persisted ledger state (operator {} -> partner {})",
            ledger.operator_key(), ledger.reserves_key().to_string());
        Ok(())
    }

    /// Persist an audit ledger to storage
    pub(super) fn persist_audit_ledger_state(&self, operator_id: PublicKey, reserves_id: &str, ledger: &Ledger) -> Result<(), DepositsError> {
        // Use a hash of the two pubkeys to create a shorter key
        use bitcoin::hashes::{sha256, Hash};
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&operator_id.serialize());
        hash_input.extend_from_slice(reserves_id.as_bytes());
        let hash = sha256::Hash::hash(&hash_input);
        let key = format!("audit_{}", hex::encode(&hash[..]));


        // Serialize a wrapper that includes operator and partner IDs
        #[derive(serde::Serialize, serde::Deserialize)]
        struct AuditLedgerWrapper {
            operator_id: Vec<u8>,
            reserves_id: String,
            ledger: Ledger,
        }

        let wrapper = AuditLedgerWrapper {
            operator_id: operator_id.serialize().to_vec(),
            reserves_id: reserves_id.to_string(),
            ledger: ledger.clone(),
        };

        let serialized = bincode::serialize(&wrapper)
            .map_err(|e| {
                log_error!(self.logger, "Failed to serialize audit ledger: {}", e);
                deposits_core::DepositsError::SerializationError
            })?;


        self.kv_store.write("deposits", "audit_ledgers", &key, serialized)
            .map_err(|e| {
                deposits_core::DepositsError::PersistenceFailed { reason: e.to_string() }
            })?;

        log_debug!(self.logger, "Persisted audit ledger state for (operator={}, partner={})", operator_id, reserves_id);
        Ok(())
    }
}
