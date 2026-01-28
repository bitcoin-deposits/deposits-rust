// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Ledger initialization operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for:
//! - Creating new ledgers as operator or partner
//! - Loading ledger state from storage
//! - Parsing ledger keys

use bitcoin::secp256k1::PublicKey;
use std::sync::{Arc, RwLock};

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use deposits_core::{Ledger, LedgerRole, LedgerManager};
use super::ledger_ext::LedgerExt;
use super::messages::{DepositsMessage, HandshakeMsg};
use deposits_core::{log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Load a channel ledger from storage
    /// Loads the ledger where we are the operator and partner_id is the partner
    fn load_ledger_state(&self, partner_id: PublicKey) -> Result<Option<Ledger>, DepositsError> {
        // Key format: ledger_{hash} where hash = SHA256(operator_pubkey || partner_pubkey)
        use bitcoin::hashes::{Hash, sha256};
        let mut key_input = Vec::new();
        key_input.extend_from_slice(&self.our_node_id.serialize());
        key_input.extend_from_slice(&partner_id.serialize());
        let key_hash = sha256::Hash::hash(&key_input);
        let key = format!("ledger_{}", hex::encode(key_hash.as_byte_array()));
        match self.kv_store.read("deposits", "ledgers", &key) {
            Ok(data) => {

                // Check if it looks like JSON (starts with '{' or '[')
                if data.len() > 0 && (data[0] == b'{' || data[0] == b'[') {
                }

                // Try to deserialize with current format
                match bincode::deserialize::<Ledger>(&data) {
                    Ok(ledger) => {
                        Ok(Some(ledger))
                    }
                    Err(e) => {
                        // Incompatible format - fail startup
                        return Err(deposits_core::DepositsError::PersistenceFailed {
                            reason: format!("Incompatible ledger format for partner {}: {}", partner_id, e)
                        });
                    }
                }
            }
            Err(_e) => {
                Ok(None) // Ledger doesn't exist yet
            }
        }
    }

    /// Check if a storage key is a ledger key
    /// New format: "ledger_{hash}" where hash is SHA256(operator || partner)
    /// We can't parse the operator/partner from the hash, so we just verify it's a ledger key
    pub(super) fn is_ledger_key(&self, key: &str) -> bool {
        key.starts_with("ledger_") && key.len() == 71 // "ledger_" + 64 hex chars
    }

    fn parse_audit_ledger_key(&self, key: &str) -> Option<[u8; 32]> {
        // Format: audit_{hash_hex}
        // We can't reconstruct the operator/partner IDs from the hash,
        // so we'll need to store that mapping separately or use a different approach
        // For now, just return the hash
        if let Some(hex_str) = key.strip_prefix("audit_") {
            if let Ok(hash_bytes) = hex::decode(hex_str) {
                if hash_bytes.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hash_bytes);
                    return Some(hash);
                }
            }
        }
        None
    }

    /// Load an audit ledger from storage
    fn load_audit_ledger_state(&self, operator_id: PublicKey, partner_id: PublicKey) -> Result<Option<Ledger>, DepositsError> {
        use bitcoin::hashes::{sha256, Hash};
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&operator_id.serialize());
        hash_input.extend_from_slice(&partner_id.serialize());
        let hash = sha256::Hash::hash(&hash_input);
        let key = format!("audit_{}", hex::encode(&hash[..]));

        match self.kv_store.read("deposits", "audit_ledgers", &key) {
            Ok(data) => {
                match bincode::deserialize::<Ledger>(&data) {
                    Ok(ledger) => {
                        Ok(Some(ledger))
                    }
                    Err(_e) => {
                        Err(DepositsError::SerializationError)
                    }
                }
            }
            Err(e) => {
                if e.to_string().contains("not found") {
                    Ok(None)
                } else {
                    Err(DepositsError::PersistenceFailed { reason: e.to_string() })
                }
            }
        }
    }

    pub fn initialize_ledger(
        &self,
        partner_node_id: PublicKey,
        multisig_address: bitcoin::Address,
    ) -> Result<(), DepositsError> {
        // Idempotency check: if ledger already exists, return error
        {
            let ledgers = self.ledgers.lock().unwrap();
            if ledgers.contains_key(&(self.our_node_id, partner_node_id)) {
                return Err(DepositsError::LedgerAlreadyExists);
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

        // Create handshake message
        let handshake_msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
            min_protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
            features: 0,
            operator_id: self.our_node_id,
            partner_id: partner_node_id,
            ledger_address: multisig_address.to_string(),
            funding_txid,
            funding_vout,
        });

        // Use LedgerManager to create the ledger (we are operator)
        // The handshake_msg is a protocol message, not a ledger operation, so we use create_empty_ledger
        let (_manager, _genesis_hash) = LedgerManager::create_empty_ledger(
            self.our_node_id,
            partner_node_id,
            LedgerRole::Operator,
            Vec::new(), // No collateral partners yet
            multisig_address.to_string(),
        );

        // Extract the ledger from manager and append the handshake message to history
        let mut ledger = _manager.into_ledger();
        log_info!(self.logger, "DEBUG: Before append_v1_mut, history len = {}", ledger.history.len());
        let hash = ledger.append_v1_mut(handshake_msg)?;
        log_info!(self.logger, "DEBUG: After append_v1_mut, history len = {}, new hash = {:02x?}",
            ledger.history.len(), &hash[0..8]);

        // Persist the ledger to storage
        self.persist_ledger_state(&ledger)?;
        log_info!(self.logger, "DEBUG: Persisted ledger with {} history entries", ledger.history.len());

        // Store the ledger in memory - we are the operator
        let mut ledgers = self.ledgers.lock().unwrap();
        ledgers.insert((self.our_node_id, partner_node_id), Arc::new(RwLock::new(ledger)));
        drop(ledgers);

        // Create the quorum for this ledger so collateral partners can be added later
        if let Err(e) = self.quorum_manager.create_quorum(self.our_node_id, partner_node_id) {
            log_warn!(self.logger, "Failed to create quorum for ledger ({}, {}): {:?}",
                self.our_node_id, partner_node_id, e);
        } else {
            log_info!(self.logger, "Created quorum for ledger ({}, {})",
                self.our_node_id, partner_node_id);
        }

        log_info!(self.logger, "Initialized and persisted ledger for partner: {} with hash {:02x?}",
            partner_node_id, &_genesis_hash[0..8]);
        Ok(())
    }

    /// Initialize a ledger where the other party is the operator, using the exact LedgerOpenRequest message received
    pub fn initialize_ledger_as_partner_with_message(
        &self,
        operator_node_id: PublicKey,
        multisig_address: bitcoin::Address,
        handshake_msg: HandshakeMsg,
    ) -> Result<(), DepositsError> {
        // Use LedgerManager to create the ledger (they are operator, we are partner)
        // The handshake_msg is a protocol message, not a ledger operation, so we use create_empty_ledger
        let (_manager, _genesis_hash) = LedgerManager::create_empty_ledger(
            operator_node_id,
            self.our_node_id,
            LedgerRole::Partner,
            Vec::new(), // No collateral partners yet
            multisig_address.to_string(),
        );

        // Extract the ledger from validator and append the handshake message to history
        let mut ledger = _manager.into_ledger();
        ledger.append_v1_mut(DepositsMessage::Handshake(handshake_msg))?;

        // Persist the ledger to storage
        self.persist_ledger_state(&ledger)?;

        // Store the ledger in memory - operator_node_id is the operator, we are partner
        let mut ledgers = self.ledgers.lock().unwrap();
        ledgers.insert((operator_node_id, self.our_node_id), Arc::new(RwLock::new(ledger)));
        drop(ledgers);

        // Create the quorum for this ledger so collateral partners can be tracked
        if let Err(e) = self.quorum_manager.create_quorum(operator_node_id, self.our_node_id) {
            log_warn!(self.logger, "Failed to create quorum for ledger ({}, {}): {:?}",
                operator_node_id, self.our_node_id, e);
        } else {
            log_info!(self.logger, "Created quorum for ledger ({}, {})",
                operator_node_id, self.our_node_id);
        }

        log_info!(self.logger, "Initialized and persisted ledger as partner with operator: {} with hash {:02x?}",
            operator_node_id, &_genesis_hash[0..8]);
        Ok(())
    }

    /// Initialize a ledger where the other party is the operator (used when responding to handshake)
    /// NOTE: This function is not currently used - prefer initialize_ledger_as_partner_with_message
    pub fn initialize_ledger_as_partner(
        &self,
        operator_node_id: PublicKey,
        multisig_address: bitcoin::Address,
    ) -> Result<(), DepositsError> {
        // Get funding outpoint for the channel with the operator
        let (funding_txid, funding_vout) = if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&operator_node_id);
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

        // Create handshake message
        let handshake_msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
            min_protocol_version: deposits_core::constants::DEPOSITS_PROTOCOL_VERSION,
            features: 0,
            operator_id: operator_node_id,
            partner_id: self.our_node_id,
            ledger_address: multisig_address.to_string(),
            funding_txid,
            funding_vout,
        });

        // Use LedgerManager to create the ledger (they are operator, we are partner)
        // The handshake_msg is a protocol message, not a ledger operation, so we use create_empty_ledger
        let (_manager, _genesis_hash) = LedgerManager::create_empty_ledger(
            operator_node_id,
            self.our_node_id,
            LedgerRole::Partner,
            Vec::new(), // No collateral partners yet
            multisig_address.to_string(),
        );

        // Extract the ledger from validator and append the handshake message to history
        let mut ledger = _manager.into_ledger();
        ledger.append_v1_mut(handshake_msg)?;

        // Persist the ledger to storage
        self.persist_ledger_state(&ledger)?;

        // Store the ledger in memory - operator_node_id is the operator, we are partner
        let mut ledgers = self.ledgers.lock().unwrap();
        ledgers.insert((operator_node_id, self.our_node_id), Arc::new(RwLock::new(ledger)));
        drop(ledgers);

        // Create the quorum for this ledger so collateral partners can be tracked
        if let Err(e) = self.quorum_manager.create_quorum(operator_node_id, self.our_node_id) {
            log_warn!(self.logger, "Failed to create quorum for ledger ({}, {}): {:?}",
                operator_node_id, self.our_node_id, e);
        } else {
            log_info!(self.logger, "Created quorum for ledger ({}, {})",
                operator_node_id, self.our_node_id);
        }

        log_info!(self.logger, "Initialized and persisted ledger as partner with operator: {} with hash {:02x?}",
            operator_node_id, &_genesis_hash[0..8]);
        Ok(())
    }
}
