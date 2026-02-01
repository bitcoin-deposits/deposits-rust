// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! # Ledger System
//!
//! Re-exports the core Ledger from deposits-core with LDK-specific extensions.
//!
//! - `Ledger`: Core ledger from deposits-core
//! - `LedgerExt`: LDK-specific extension methods (construct_voter_set, message handling)
//! - `LedgerValidator`: Stateless validation utilities (re-exported from deposits-core)
//! - `LedgerManager`: Complex multi-step operations (re-exported from deposits-core)

use bitcoin::secp256k1::PublicKey;

use super::messages::DepositsMessage;
use crate::wire::messages::CollateralAttestationMsg;
use deposits_core::SignedLedgerUpdate;
use deposits_core::DepositsError;

// Re-export core types from deposits-core
pub use deposits_core::ledger::{Ledger, LedgerRole, LedgerUpdate, LedgerValidator, LedgerManager};

// =============================================================================
// SignedLedgerUpdate Extension Trait
// =============================================================================

/// Extension trait for decoding messages from SignedLedgerUpdate.
///
/// The deposits-core SignedLedgerUpdate stores serialized message bytes.
/// This trait provides methods to decode them into ldk-node's DepositsMessage type
/// or extract the LedgerOperation.
pub trait SignedLedgerUpdateExt {
    /// Decode the message bytes into a DepositsMessage.
    fn get_message(&self) -> Result<DepositsMessage, DepositsError>;

    /// Extract the LedgerOperation from the message bytes.
    /// Returns None if the message doesn't represent a ledger operation.
    fn get_operation(&self) -> Option<deposits_core::messages::LedgerOperation>;
}

impl SignedLedgerUpdateExt for deposits_core::types::SignedLedgerUpdate {
    fn get_message(&self) -> Result<DepositsMessage, DepositsError> {
        use lightning::ln::wire::CustomMessageReader;
        use super::messages::DepositsMessageReader;

        // The message bytes were written using Writeable trait,
        // so we must read using the CustomMessageReader which dispatches
        // based on message_type to the correct Readable implementation.
        let reader = DepositsMessageReader;
        // Use slice reference which implements LengthLimitedRead
        let mut slice = self.message.as_slice();
        reader.read(self.message_type, &mut slice)
            .map_err(|_| DepositsError::SerializationError)?
            .ok_or(DepositsError::SerializationError)
    }

    fn get_operation(&self) -> Option<deposits_core::messages::LedgerOperation> {
        // First try to decode using the stored message_type
        if let Ok(msg) = self.get_message() {
            return msg.to_operation();
        }

        // Fallback: try decoding from raw bytes (may have type prefix)
        if self.message.len() >= 2 {
            let msg_type = u16::from_be_bytes([self.message[0], self.message[1]]);
            let msg_data = &self.message[2..];
            if let Ok(msg) = crate::wire::MessageCodec::decode_message_with_type(msg_type, msg_data) {
                return msg.to_operation();
            }
        }

        None
    }
}

// =============================================================================
// LDK-Specific Extension Trait
// =============================================================================

/// Extension trait for LDK-specific Ledger functionality.
///
/// These methods are specific to the LDK integration layer and handle:
/// - Taproot reserves output construction (VoterSet)
/// - Message format handling (DepositsMessage enum)
pub trait LedgerExt {
    /// Construct the VoterSet for this ledger's reserves output.
    ///
    /// The VoterSet is used to build Taproot reserves outputs with tiered recovery.
    fn construct_voter_set(&self) -> deposits_core::VoterSet;

    /// Compute what the hash would be if we appended this message.
    /// Returns (prev_hash, new_hash) without actually modifying the ledger.
    fn compute_next_hash(&self, message: &DepositsMessage) -> ([u8; 32], [u8; 32]);

    /// Predict what the ledger hash would be after appending a message, WITHOUT modifying the ledger.
    /// Returns (prev_hash, predicted_hash, sequence_number).
    fn predict_hash_after(&self, message: &DepositsMessage) -> ([u8; 32], [u8; 32], u64);

    /// Apply state changes from a message WITHOUT creating a hash chain entry.
    fn apply_state_only(&mut self, message: &DepositsMessage) -> Result<(), DepositsError>;

    /// Append a message to the ledger (immutable/functional style).
    /// Usage: `let (ledger, hash) = ledger.append(msg)?;`
    fn append(self, message: DepositsMessage) -> Result<(Self, [u8; 32]), DepositsError> where Self: Sized;

    /// Mutable version of append for compatibility with RwLock guards.
    fn append_mut(&mut self, message: DepositsMessage) -> Result<[u8; 32], DepositsError>;

    /// Append and return both prev_hash and new_hash atomically.
    /// Returns (prev_hash, new_hash, sequence_number).
    fn append_mut_with_metadata(&mut self, message: DepositsMessage) -> Result<([u8; 32], [u8; 32], u64), DepositsError>;

    /// Append a signed update to the ledger (validates hash chain continuity).
    fn append_signed(&mut self, update: SignedLedgerUpdate) -> Result<(), DepositsError>;

    /// Insert a signed update by sequence number WITHOUT strict chain validation.
    /// Used for Partners receiving SignedAuditUpdate broadcasts.
    fn insert_signed_unchecked(&mut self, update: SignedLedgerUpdate) -> usize;

    /// Update or add a collateral attestation from a quorum member.
    fn update_collateral_attestation(
        &mut self,
        partner: PublicKey,
        attestation: CollateralAttestationMsg,
    ) -> Result<(), DepositsError>;

    /// Check if adding a deposit with given amount would satisfy collateral requirements.
    fn can_add_deposit(
        &self,
        amount: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> Result<(), DepositsError>;

    /// Check if crediting a payment would satisfy collateral requirements.
    fn can_credit_payment(
        &self,
        amount: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> Result<(), DepositsError>;
}

impl LedgerExt for Ledger {
    fn construct_voter_set(&self) -> deposits_core::VoterSet {
        use std::str::FromStr;
        // In LDK, reserves_key is the partner's pubkey stored as a string
        let reserves_pubkey = bitcoin::secp256k1::PublicKey::from_str(&self.state.reserves_key)
            .expect("reserves_key should be valid pubkey string");
        deposits_core::VoterSet::new(
            reserves_pubkey,
            self.state.quorum_members.clone(),
        )
    }

    fn compute_next_hash(&self, message: &DepositsMessage) -> ([u8; 32], [u8; 32]) {
        use bitcoin::hashes::{Hash, sha256};
        use lightning::util::ser::Writeable;

        let prev_hash = self.tail_hash();
        let sequence_number = self.history.len() as u64;

        let mut message_bytes = Vec::new();
        message.write(&mut message_bytes).expect("Message encoding should never fail");

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence_number.to_le_bytes());
        hash_input.extend_from_slice(&prev_hash);
        hash_input.extend_from_slice(&message_bytes);

        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();
        (prev_hash, new_hash)
    }

    fn predict_hash_after(&self, message: &DepositsMessage) -> ([u8; 32], [u8; 32], u64) {
        let (prev_hash, predicted_hash) = self.compute_next_hash(message);
        let sequence_number = self.history.len() as u64;
        (prev_hash, predicted_hash, sequence_number)
    }

    fn apply_state_only(&mut self, message: &DepositsMessage) -> Result<(), DepositsError> {
        // Extract operation from V2 message and apply to state
        if let Some(operation) = message.to_operation() {
            self.apply_state_changes(&operation)?;
        } else {
            // Handle special messages that don't have a LedgerOperation
            match message {
                DepositsMessage::Handshake(_) => {
                    // Ledger opened - state already initialized
                }
                DepositsMessage::LedgerUpdate(ref update_msg) => {
                    // V2 CollateralAttestation is inside LedgerUpdate
                    if let deposits_core::messages::LedgerOperation::CollateralAttestation { collateral_operator, quorum_member, amount, block_height, lock_until_block, signature, ledger_hash } = &update_msg.operation {
                        // Check if this partner is relevant (is our direct partner or a quorum member)
                        if quorum_member.to_string() == self.state.reserves_key || self.state.quorum_members.contains(quorum_member) {
                            let attestation = deposits_core::CollateralAttestation {
                                operator_id: *collateral_operator,
                                quorum_member: *quorum_member,
                                amount: *amount,
                                block_height: *block_height,
                                lock_until_block: *lock_until_block,
                                signature: *signature,
                                ledger_hash: *ledger_hash,
                            };
                            self.state.collateral_attestations.insert(*quorum_member, attestation);
                        }
                    }
                }
                _ => {
                    // Other message types don't affect state
                }
            }
        }
        self.state.last_updated = deposits_core::now_unix_timestamp();
        Ok(())
    }

    fn append(mut self, message: DepositsMessage) -> Result<(Self, [u8; 32]), DepositsError> {
        use lightning::util::ser::Writeable;

        // Check if ledger is closed
        if self.is_closed() {
            return Err(DepositsError::InvalidState(
                "Cannot append to closed ledger".to_string()
            ));
        }

        // Validate sequence number if message contains one
        let expected_sequence = self.history.len() as u64;
        if let Some(sequence_number) = message.get_sequence_number() {
            if sequence_number != expected_sequence {
                return Err(DepositsError::InvalidState(
                    format!("Sequence number mismatch: expected {}, got {}", expected_sequence, sequence_number)
                ));
            }
        }

        // Create the update
        let mut message_bytes = Vec::new();
        message.write(&mut message_bytes).expect("Message encoding should never fail");
        let prev_hash = self.tail_hash();

        use bitcoin::hashes::{Hash, sha256};
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&expected_sequence.to_le_bytes());
        hash_input.extend_from_slice(&prev_hash);
        hash_input.extend_from_slice(&message_bytes);
        let update_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Convert to SignedLedgerUpdate
        let signed_update = deposits_core::types::SignedLedgerUpdate {
            message: message_bytes,
            message_type: message.message_type(),
            operator_signature: [0u8; 64], // Placeholder during migration
            partner_signature: [0u8; 64],
            operator_id: self.state.operator_key,
            reserves_id: self.state.reserves_key.clone(),
            sequence_number: expected_sequence,
            previous_hash: prev_hash,
            current_hash: update_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: 0,
            block_hash: [0u8; 32],
        };

        // Apply state transition
        self.apply_state_only(&message)?;

        // Append to history
        self.history.push(signed_update);

        Ok((self, update_hash))
    }

    fn append_mut(&mut self, message: DepositsMessage) -> Result<[u8; 32], DepositsError> {
        let cloned = self.clone();
        let (new_ledger, hash) = cloned.append(message)?;
        *self = new_ledger;
        Ok(hash)
    }

    fn append_mut_with_metadata(&mut self, message: DepositsMessage) -> Result<([u8; 32], [u8; 32], u64), DepositsError> {
        let prev_hash = self.tail_hash();
        let sequence_before = self.history.len() as u64;
        let new_hash = self.append_mut(message)?;
        Ok((prev_hash, new_hash, sequence_before))
    }

    fn append_signed(&mut self, update: SignedLedgerUpdate) -> Result<(), DepositsError> {
        // Verify chain continuity
        let expected_prev = self.tail_hash();
        if update.previous_hash != expected_prev {
            return Err(DepositsError::InvalidState(
                format!("Hash mismatch: expected {:?}, got {:?}",
                    hex::encode(expected_prev), hex::encode(update.previous_hash))
            ));
        }

        // Verify sequence number
        let expected_seq = self.history.len() as u64;
        if update.sequence_number != expected_seq {
            return Err(DepositsError::InvalidState(
                format!("Sequence mismatch: expected {}, got {}",
                    expected_seq, update.sequence_number)
            ));
        }

        // Deserialize and apply state change using SignedLedgerUpdateExt
        if let Ok(msg) = update.get_message() {
            self.apply_state_only(&msg)?;
        }

        // SignedLedgerUpdate is already the deposits-core type (re-exported in types.rs)
        self.history.push(update);
        Ok(())
    }

    fn insert_signed_unchecked(&mut self, update: SignedLedgerUpdate) -> usize {
        let seq = update.sequence_number;
        let index = seq as usize;
        let expected_index = self.history.len();

        // SignedLedgerUpdate is already the deposits-core type (re-exported in types.rs)
        // Normal case: appending in order
        if index == expected_index {
            self.history.push(update);
            // Flush pending updates
            let mut flushed = 0;
            loop {
                let next_seq = self.history.len() as u64;
                if let Some(pending) = self.state.pending_updates.remove(&next_seq) {
                    self.history.push(pending);
                    flushed += 1;
                } else {
                    break;
                }
            }
            return 1 + flushed;
        }

        // Already have this update - update in place with signature preservation
        if index < expected_index {
            let existing_partner_sig = self.history[index].partner_signature;
            let incoming_partner_sig = update.partner_signature;
            if existing_partner_sig != [0u8; 64] && incoming_partner_sig == [0u8; 64] {
                let mut merged = update;
                merged.partner_signature = existing_partner_sig;
                self.history[index] = merged;
            } else {
                self.history[index] = update;
            }
            return 1;
        }

        // Out of order - queue for later
        self.state.pending_updates.insert(seq, update);
        0
    }

    fn update_collateral_attestation(
        &mut self,
        partner: PublicKey,
        attestation: CollateralAttestationMsg,
    ) -> Result<(), DepositsError> {
        if !self.state.quorum_members.contains(&partner) {
            return Err(DepositsError::InvalidState(
                format!("Partner {} is not a quorum member for this ledger", partner)
            ));
        }
        // Convert wire attestation to core type
        let core_attestation = deposits_core::CollateralAttestation {
            operator_id: attestation.operator,
            quorum_member: attestation.quorum_member,
            amount: attestation.amount,
            block_height: attestation.block_height,
            lock_until_block: attestation.lock_until_block,
            signature: attestation.signature,
            ledger_hash: attestation.ledger_hash,
        };
        self.state.collateral_attestations.insert(partner, core_attestation);
        Ok(())
    }

    fn can_add_deposit(
        &self,
        amount: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> Result<(), DepositsError> {
        let new_liability = self.total_deposit_liability().saturating_add(amount);
        self.validate_collateral_for_liability(new_liability, current_block, max_attestation_age_blocks)
    }

    fn can_credit_payment(
        &self,
        amount: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> Result<(), DepositsError> {
        let new_liability = self.total_deposit_liability().saturating_add(amount);
        self.validate_collateral_for_liability(new_liability, current_block, max_attestation_age_blocks)
    }
}

// =============================================================================
// SignedLedgerUpdateLog Extension Trait
// =============================================================================

/// Extension trait for SignedLedgerUpdateLog with additional convenience methods.
///
/// These methods provide functionality for the handler code.
pub trait SignedLedgerUpdateLogExt {
    /// Add an update to the log.
    fn add_update(&mut self, update: deposits_core::SignedLedgerUpdate) -> Result<(), DepositsError>;

    /// Verify the hash chain integrity.
    fn verify_chain(&self) -> Result<(), DepositsError>;

    /// Get updates since a given sequence number.
    fn get_updates_since(&self, since_sequence: u64) -> Vec<deposits_core::SignedLedgerUpdate>;

    /// Create the data to be signed for an update.
    fn create_signing_data(update: &deposits_core::SignedLedgerUpdate) -> Vec<u8>;
}

impl SignedLedgerUpdateLogExt for deposits_core::SignedLedgerUpdateLog {
    fn add_update(&mut self, update: deposits_core::SignedLedgerUpdate) -> Result<(), DepositsError> {
        // Delegate to the core implementation
        deposits_core::SignedLedgerUpdateLog::add_update(self, update)
    }

    fn verify_chain(&self) -> Result<(), DepositsError> {
        // Delegate to the core implementation
        deposits_core::SignedLedgerUpdateLog::verify_chain(self)
    }

    fn get_updates_since(&self, since_sequence: u64) -> Vec<deposits_core::SignedLedgerUpdate> {
        // Delegate to the core implementation
        deposits_core::SignedLedgerUpdateLog::get_updates_since(self, since_sequence)
    }

    fn create_signing_data(update: &deposits_core::SignedLedgerUpdate) -> Vec<u8> {
        // Delegate to the core implementation - partner_signing_data provides the same format
        update.partner_signing_data()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use deposits_core::TapscriptReservesBuilder;

    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        let sk = SecretKey::from_slice(&secret).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_construct_voter_set_two_party() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );

        let voter_set = ledger.construct_voter_set();

        // In 2-party case: partner is tie-breaker, no other voters
        assert_eq!(voter_set.total_count(), 1);
        assert_eq!(voter_set.primary_count(), 0);
        assert!(voter_set.tie_breaker().is_some());
        assert_eq!(voter_set.tie_breaker().unwrap().pubkey, partner);
    }

    #[test]
    fn test_construct_voter_set_multi_party() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral1 = generate_test_pubkey(3);
        let collateral2 = generate_test_pubkey(4);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );
        ledger.add_quorum_member(collateral1).unwrap();
        ledger.add_quorum_member(collateral2).unwrap();

        let voter_set = ledger.construct_voter_set();

        // In multi-party case: partner is tie-breaker, quorum members are voters
        assert_eq!(voter_set.total_count(), 3);
        assert_eq!(voter_set.primary_count(), 2);
        assert!(voter_set.tie_breaker().is_some());
        assert_eq!(voter_set.tie_breaker().unwrap().pubkey, partner);
    }

    #[test]
    fn test_construct_voter_set_produces_valid_taproot() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );
        ledger.add_quorum_member(collateral).unwrap();

        let voter_set = ledger.construct_voter_set();
        let ledger_hash = [0xAB; 32];

        let builder = TapscriptReservesBuilder::with_defaults(
            voter_set,
            bitcoin::Network::Regtest,
            ledger_hash,
        );
        let output = builder.build().expect("Should build valid Taproot output");

        assert!(output.script_pubkey().is_p2tr());
    }

    #[test]
    fn test_quorum_participants() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral1 = generate_test_pubkey(3);
        let collateral2 = generate_test_pubkey(4);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );
        ledger.add_quorum_member(collateral1).unwrap();
        ledger.add_quorum_member(collateral2).unwrap();

        let participants = ledger.quorum_participants();
        assert_eq!(participants.len(), 4);
        assert!(participants.contains(&operator));
        assert!(participants.contains(&partner));
        assert!(participants.contains(&collateral1));
        assert!(participants.contains(&collateral2));
    }

    #[test]
    fn test_all_partners() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );
        ledger.add_quorum_member(collateral).unwrap();

        let partners = ledger.all_partners();
        assert_eq!(partners.len(), 2);
        assert!(partners.contains(&partner));
        assert!(partners.contains(&collateral));
        assert!(!partners.contains(&operator));
    }

    #[test]
    fn test_add_quorum_member_success() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );

        assert!(ledger.state.quorum_members.is_empty());

        let new_collateral = generate_test_pubkey(3);
        let result = ledger.add_quorum_member(new_collateral);
        assert!(result.is_ok());
        assert_eq!(ledger.state.quorum_members.len(), 1);
        assert!(ledger.state.quorum_members.contains(&new_collateral));
    }

    #[test]
    fn test_add_quorum_member_rejects_operator() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );

        let result = ledger.add_quorum_member(operator);
        assert!(result.is_err());
        assert!(ledger.state.quorum_members.is_empty());
    }

    #[test]
    fn test_add_quorum_member_rejects_channel_partner() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );

        let result = ledger.add_quorum_member(partner);
        assert!(result.is_err());
        assert!(ledger.state.quorum_members.is_empty());
    }

    #[test]
    fn test_add_quorum_member_rejects_duplicate() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        let mut ledger = Ledger::new_as_operator(
            operator,
            partner.to_string(),
            "test_address".to_string(),
        );

        assert!(ledger.add_quorum_member(collateral).is_ok());
        let result = ledger.add_quorum_member(collateral);
        assert!(result.is_err());
        assert_eq!(ledger.state.quorum_members.len(), 1);
    }
}
