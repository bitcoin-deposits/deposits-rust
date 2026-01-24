//! Ledger Operations for Bitcoin Deposits
//!
//! This module provides ledger query and management operations including
//! hash lookups, ledger listing, and update retrieval.
//!
//! The core trait `LedgerOperations` is re-exported from deposits-core.
//! This module extends it with LDK-specific methods in `LedgerOperationsExt`.

use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use deposits_core::DepositsError;
use deposits_core::Ledger;
use deposits_core::SignedLedgerUpdate;
use deposits_core::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export the core trait from deposits-core
pub use deposits_core::handler_traits::LedgerOperations;

/// Extension trait for LDK-specific ledger operations on DepositsHandler
///
/// These methods use LDK-specific types like `Arc<RwLock<Ledger>>` and
/// cannot be defined in deposits-core.
pub trait LedgerOperationsExt {
    /// Get all ledger hashes for ledgers where we are operator
    fn get_all_ledger_hashes(&self) -> HashMap<PublicKey, [u8; 32]>;

    /// Get the next sequence number for a message involving the given deposit pubkey
    fn get_next_sequence_number_for_deposit(&self, deposit_pubkey: PublicKey) -> Result<(u64, PublicKey), DepositsError>;

    /// Get the ledger address for a specific partner
    fn get_ledger_address(&self, partner_node_id: PublicKey) -> Result<String, DepositsError>;

    /// Get the update history for a specific ledger
    fn get_ledger_updates(&self, partner_node_id: PublicKey) -> Result<Vec<SignedLedgerUpdate>, DepositsError>;

    /// Get synchronization state (ACK and commitment hashes) for a ledger
    fn get_ledger_sync_state(&self, partner_node_id: PublicKey) -> Result<([u8; 32], [u8; 32]), DepositsError>;

    /// Get all ledger updates for all partners
    fn get_all_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>>;

    /// Get all audit ledger updates (third-party ledgers we're monitoring)
    fn get_all_audit_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>>;

    /// Get all signed audit updates (cryptographically signed third-party ledgers)
    fn get_all_signed_audit_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>>;

    /// Get a partner ledger (for when we are the partner)
    fn get_partner_ledger(&self, operator_id: &PublicKey) -> Option<Arc<RwLock<Ledger>>>;

    /// Get all ledgers
    fn get_all_ledgers(&self) -> Vec<((PublicKey, PublicKey), Arc<RwLock<Ledger>>)>;

    /// Get all partner ledger updates
    fn get_all_partner_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>>;

    /// Find the partner ID for a deposit pubkey
    fn find_partner_for_deposit(&self, deposit_pubkey: PublicKey) -> Option<PublicKey>;

    /// Drop all ledgers (for testing)
    fn drop_all_ledgers(&self) -> usize;

    /// Close a ledger with a partner
    fn close_ledger(&self, partner_node_id: PublicKey) -> Result<(), DepositsError>;

    /// Mark a ledger as committed at a specific commitment number
    fn mark_ledger_committed(&self, partner_node_id: PublicKey, commitment_number: u64) -> Result<(), DepositsError>;

    /// Get the ledger hash for the current commitment
    fn get_ledger_hash_for_commitment(&self, partner_node_id: PublicKey) -> Result<Option<[u8; 32]>, DepositsError>;
}

// Implement the core LedgerOperations trait from deposits-core
impl<L: Deref + Clone> LedgerOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_ledger_hash(&self, partner_node_id: PublicKey) -> Result<[u8; 32], DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger.read().unwrap();
            Ok(ledger.tail_hash())
        } else {
            Ok([0u8; 32])
        }
    }

    fn get_ledger_hashes(&self, partner_node_id: PublicKey) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        let ledgers = self.ledgers.lock().unwrap();

        let local_hash = ledgers
            .get(&(self.our_node_id, partner_node_id))
            .map(|ledger| ledger.read().unwrap().state.channel_deepest_commitment_hash);

        let remote_hash = ledgers
            .get(&(partner_node_id, self.our_node_id))
            .map(|ledger| ledger.read().unwrap().state.channel_deepest_commitment_hash);

        (local_hash, remote_hash)
    }

    fn get_committed_ledger_hashes_from_channel(
        &self,
        counterparty_node_id: PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        let Some(ref cm) = self.channel_manager else {
            return (None, None);
        };

        let channels = cm.list_channels();
        let channel = channels.iter().find(|ch| ch.counterparty_node_id == counterparty_node_id);

        let Some(ch) = channel else {
            return (None, None);
        };

        let local_hash = ch.local_reserves.as_ref().map(|r| r.1);
        let remote_hash = ch.remote_reserves.as_ref().map(|r| r.1);

        (local_hash, remote_hash)
    }

    fn validate_ledger_hash_for_reserves(
        &self,
        counterparty_node_id: &PublicKey,
        ledger_hash: &[u8; 32],
    ) -> bool {
        // Zero hash is always valid
        if ledger_hash == &[0u8; 32] {
            log_debug!(self.logger, "Accepting zero ledger hash for reserves with partner {}",
                counterparty_node_id);
            return true;
        }

        let ledgers = self.ledgers.lock().unwrap();
        let ledger_key = (*counterparty_node_id, self.our_node_id);

        if let Some(ledger_arc) = ledgers.get(&ledger_key) {
            let ledger = ledger_arc.read().unwrap();

            // Check if the hash exists in the ledger's update chain
            let hash_exists = ledger.history.iter().any(|update| {
                update.current_state_hash == *ledger_hash
            });

            if hash_exists {
                log_debug!(self.logger, "Validated ledger hash {} for reserves with partner {}",
                    crate::hex_utils::to_string(ledger_hash),
                    counterparty_node_id);
                return true;
            }

            // Also check if it's the current tail hash
            if ledger.tail_hash() == *ledger_hash {
                log_debug!(self.logger, "Validated ledger hash {} (tail) for reserves with partner {}",
                    crate::hex_utils::to_string(ledger_hash),
                    counterparty_node_id);
                return true;
            }
        }

        log_debug!(self.logger, "Rejecting unknown ledger hash {} for reserves with partner {}",
            crate::hex_utils::to_string(ledger_hash),
            counterparty_node_id);
        false
    }

    fn get_ledger_sequence(&self, partner_node_id: PublicKey) -> Result<u64, DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(ledger.history.len() as u64);
        }

        Err(DepositsError::LedgerNotFound)
    }

    fn has_ledger_with(&self, partner_node_id: PublicKey) -> bool {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.contains_key(&(self.our_node_id, partner_node_id))
    }

    fn list_operator_ledgers(&self) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.keys()
            .filter(|(operator, _partner)| *operator == self.our_node_id)
            .map(|(_operator, partner)| *partner)
            .collect()
    }

    fn list_partner_ledgers(&self) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.keys()
            .filter(|(_operator, partner)| *partner == self.our_node_id)
            .map(|(operator, _partner)| *operator)
            .collect()
    }
}

// Implement the LDK-specific extension trait
impl<L: Deref + Clone> LedgerOperationsExt for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_all_ledger_hashes(&self) -> HashMap<PublicKey, [u8; 32]> {
        let ledgers = self.ledgers.lock().unwrap();
        let mut hashes = HashMap::new();

        for ((operator_id, partner_id), ledger) in ledgers.iter() {
            if *operator_id == self.our_node_id {
                let ledger = ledger.read().unwrap();
                hashes.insert(*partner_id, ledger.tail_hash());
            }
        }

        hashes
    }

    fn get_next_sequence_number_for_deposit(&self, deposit_pubkey: PublicKey) -> Result<(u64, PublicKey), DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        for ((operator, partner), ledger_arc) in ledgers.iter() {
            if *operator == self.our_node_id {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.deposits.contains_key(&deposit_pubkey) {
                    let next_sequence = ledger.history.len() as u64;
                    return Ok((next_sequence, *partner));
                }
            }
        }

        Err(DepositsError::DepositNotFound)
    }

    fn get_ledger_address(&self, partner_node_id: PublicKey) -> Result<String, DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(ledger.state.ledger_address.clone());
        }

        if let Some(ledger_arc) = ledgers.get(&(partner_node_id, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(ledger.state.ledger_address.clone());
        }

        Err(DepositsError::ProtocolViolation {
            violation_type: "ledger_not_found".to_string(),
            details: format!("No ledger found for partner {}", partner_node_id),
        })
    }

    fn get_ledger_updates(&self, partner_node_id: PublicKey) -> Result<Vec<SignedLedgerUpdate>, DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(ledger.history.to_vec());
        }

        if let Some(ledger_arc) = ledgers.get(&(partner_node_id, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(ledger.history.to_vec());
        }

        Err(DepositsError::ProtocolViolation {
            violation_type: "ledger_not_found".to_string(),
            details: format!("No ledger found for partner {}", partner_node_id),
        })
    }

    fn get_ledger_sync_state(&self, partner_node_id: PublicKey) -> Result<([u8; 32], [u8; 32]), DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok((ledger.state.partner_deepest_ack_hash, ledger.state.channel_deepest_commitment_hash));
        }

        if let Some(ledger_arc) = ledgers.get(&(partner_node_id, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok((ledger.state.partner_deepest_ack_hash, ledger.state.channel_deepest_commitment_hash));
        }

        Err(DepositsError::ProtocolViolation {
            violation_type: "ledger_not_found".to_string(),
            details: format!("No ledger found for partner {}", partner_node_id),
        })
    }

    fn get_all_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>> {
        let ledgers = self.ledgers.lock().unwrap();
        let mut all_updates = HashMap::new();

        log_info!(self.logger, "DEBUG get_all_ledger_updates: total ledgers in memory = {}", ledgers.len());

        for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
            if *operator_id != self.our_node_id && *partner_id != self.our_node_id {
                log_info!(self.logger, "DEBUG get_all_ledger_updates: skipping ledger {}→{} (not ours)", operator_id, partner_id);
                continue;
            }

            let ledger = ledger_arc.read().unwrap();
            log_info!(self.logger, "DEBUG get_all_ledger_updates: ledger {}→{} has {} history entries",
                operator_id, partner_id, ledger.history.len());
            all_updates.insert((*operator_id, *partner_id), ledger.history.to_vec());
        }

        all_updates
    }

    fn get_all_audit_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>> {
        let ledgers = self.ledgers.lock().unwrap();
        let mut all_updates = HashMap::new();

        for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            all_updates.insert((*operator_id, *partner_id), ledger.history.to_vec());
        }

        all_updates
    }

    fn get_all_signed_audit_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>> {
        let signed_update_logs = self.signed_update_logs.lock().unwrap();
        let mut all_updates = HashMap::new();

        for ((operator_id, partner_id), log) in signed_update_logs.iter() {
            all_updates.insert((*operator_id, *partner_id), log.updates.clone());
        }

        all_updates
    }

    fn get_partner_ledger(&self, operator_id: &PublicKey) -> Option<Arc<RwLock<Ledger>>> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.get(&(*operator_id, self.our_node_id)).cloned()
    }

    fn get_all_ledgers(&self) -> Vec<((PublicKey, PublicKey), Arc<RwLock<Ledger>>)> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    fn get_all_partner_ledger_updates(&self) -> HashMap<(PublicKey, PublicKey), Vec<SignedLedgerUpdate>> {
        let ledgers = self.ledgers.lock().unwrap();
        let mut all_updates = HashMap::new();

        for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            all_updates.insert((*operator_id, *partner_id), ledger.history.clone());
        }

        all_updates
    }

    fn find_partner_for_deposit(&self, deposit_pubkey: PublicKey) -> Option<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();

        for ((operator, partner), ledger_arc) in ledgers.iter() {
            if *operator == self.our_node_id {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.deposits.contains_key(&deposit_pubkey) {
                    return Some(*partner);
                }
            }
        }

        None
    }

    fn drop_all_ledgers(&self) -> usize {
        let mut ledgers = self.ledgers.lock().unwrap();
        let count = ledgers.len();
        ledgers.clear();
        count
    }

    fn close_ledger(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        let mut ledgers = self.ledgers.lock().unwrap();

        // Remove ledger where we are operator
        if ledgers.remove(&(self.our_node_id, partner_node_id)).is_some() {
            return Ok(());
        }

        // Remove ledger where partner is operator
        if ledgers.remove(&(partner_node_id, self.our_node_id)).is_some() {
            return Ok(());
        }

        Err(DepositsError::ProtocolViolation {
            violation_type: "ledger_not_found".to_string(),
            details: format!("No ledger found for partner {}", partner_node_id),
        })
    }

    fn mark_ledger_committed(&self, partner_node_id: PublicKey, _commitment_number: u64) -> Result<(), DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if ledgers.get(&(self.our_node_id, partner_node_id)).is_some() {
            // TODO: Track commitment state in handler
            return Ok(());
        }

        Err(DepositsError::DepositNotFound)
    }

    fn get_ledger_hash_for_commitment(&self, partner_node_id: PublicKey) -> Result<Option<[u8; 32]>, DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            return Ok(Some(ledger.tail_hash()));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;

    fn create_test_handler() -> DepositsHandler<Arc<TestLogger>> {
        let logger = Arc::new(TestLogger::new());
        DepositsHandler::new_for_testing(logger)
    }

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_get_ledger_hash_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(1);

        let hash = handler.get_ledger_hash(partner).unwrap();
        assert_eq!(hash, [0u8; 32], "No ledger should return zero hash");
    }

    #[test]
    fn test_list_operator_ledgers_empty() {
        let handler = create_test_handler();
        let ledgers = handler.list_operator_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_list_partner_ledgers_empty() {
        let handler = create_test_handler();
        let ledgers = handler.list_partner_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_get_all_ledger_hashes_empty() {
        let handler = create_test_handler();
        let hashes = handler.get_all_ledger_hashes();
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_get_ledger_address_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(2);

        let result = handler.get_ledger_address(partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_ledger_updates_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(3);

        let result = handler.get_ledger_updates(partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ledger_hash_zero() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(4);

        let is_valid = handler.validate_ledger_hash_for_reserves(&partner, &[0u8; 32]);
        assert!(is_valid, "Zero hash should always be valid");
    }

    #[test]
    fn test_find_partner_for_deposit_not_found() {
        let handler = create_test_handler();
        let deposit = create_test_pubkey(5);

        let partner = handler.find_partner_for_deposit(deposit);
        assert!(partner.is_none());
    }

    #[test]
    fn test_drop_all_ledgers_empty() {
        let handler = create_test_handler();
        let count = handler.drop_all_ledgers();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_close_ledger_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(6);

        let result = handler.close_ledger(partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_all_ledgers_empty() {
        let handler = create_test_handler();
        let ledgers = handler.get_all_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_get_partner_ledger_not_found() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(7);

        let ledger = handler.get_partner_ledger(&operator);
        assert!(ledger.is_none());
    }

    /// Helper to add an operator ledger (where handler's node is operator)
    fn add_operator_ledger(handler: &DepositsHandler<Arc<TestLogger>>, partner: PublicKey) -> [u8; 32] {
        let ledger = Ledger::new_as_operator(
            handler.our_node_id,
            partner,
            "tb1qtest".to_string(),
        );
        let hash = ledger.tail_hash();
        handler.ledgers.lock().unwrap().insert(
            (handler.our_node_id, partner),
            Arc::new(RwLock::new(ledger))
        );
        hash
    }

    /// Helper to add a partner ledger (where handler's node is partner)
    fn add_partner_ledger_test(handler: &DepositsHandler<Arc<TestLogger>>, operator: PublicKey) {
        let ledger = Ledger::new_as_operator(
            operator,
            handler.our_node_id,
            "tb1qtest_partner".to_string(),
        );
        handler.ledgers.lock().unwrap().insert(
            (operator, handler.our_node_id),
            Arc::new(RwLock::new(ledger))
        );
    }

    /// Helper to add a deposit to a ledger
    fn add_deposit_to_ledger(
        handler: &DepositsHandler<Arc<TestLogger>>,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
    ) {
        let ledgers = handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, partner)) {
            let mut ledger = ledger_arc.write().unwrap();
            // Use deposits-core Deposit type
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 100_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
        }
    }

    #[test]
    fn test_get_ledger_hash_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(10);

        let expected_hash = add_operator_ledger(&handler, partner);
        let hash = handler.get_ledger_hash(partner).unwrap();

        assert_eq!(hash, expected_hash, "Should return ledger's tail hash");
    }

    #[test]
    fn test_list_operator_ledgers_with_ledger() {
        let handler = create_test_handler();
        let partner1 = create_test_pubkey(20);
        let partner2 = create_test_pubkey(21);

        add_operator_ledger(&handler, partner1);
        add_operator_ledger(&handler, partner2);

        let ledgers = handler.list_operator_ledgers();
        assert_eq!(ledgers.len(), 2);
        assert!(ledgers.contains(&partner1));
        assert!(ledgers.contains(&partner2));
    }

    #[test]
    fn test_list_partner_ledgers_with_ledger() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(30);

        add_partner_ledger_test(&handler, operator);

        let ledgers = handler.list_partner_ledgers();
        assert_eq!(ledgers.len(), 1);
        assert!(ledgers.contains(&operator));
    }

    #[test]
    fn test_get_all_ledger_hashes_with_ledgers() {
        let handler = create_test_handler();
        let partner1 = create_test_pubkey(40);
        let partner2 = create_test_pubkey(41);

        let hash1 = add_operator_ledger(&handler, partner1);
        let hash2 = add_operator_ledger(&handler, partner2);

        let hashes = handler.get_all_ledger_hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes.get(&partner1), Some(&hash1));
        assert_eq!(hashes.get(&partner2), Some(&hash2));
    }

    #[test]
    fn test_get_ledger_address_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(50);

        add_operator_ledger(&handler, partner);

        let result = handler.get_ledger_address(partner);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "tb1qtest");
    }

    #[test]
    fn test_get_ledger_updates_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(60);

        add_operator_ledger(&handler, partner);

        let result = handler.get_ledger_updates(partner);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty()); // New ledger has no updates
    }

    #[test]
    fn test_get_ledger_sync_state_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(70);

        add_operator_ledger(&handler, partner);

        let result = handler.get_ledger_sync_state(partner);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_ledger_sync_state_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(71);

        let result = handler.get_ledger_sync_state(partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ledger_hash_unknown() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(80);

        // Add a PARTNER ledger (where partner is operator and we are partner)
        // The validate function looks up with (counterparty, our_node_id) key
        add_partner_ledger_test(&handler, partner);

        // Unknown hash should be rejected when ledger exists
        let is_valid = <DepositsHandler<_> as LedgerOperations>::validate_ledger_hash_for_reserves(
            &handler,
            &partner,
            &[0xAB; 32]
        );
        assert!(!is_valid, "Unknown hash should not be valid");
    }

    #[test]
    fn test_validate_ledger_hash_tail_hash() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(81);

        // Add a partner ledger (counterparty is operator)
        add_partner_ledger_test(&handler, partner);

        // Get the tail hash
        let ledgers = handler.ledgers.lock().unwrap();
        let tail_hash = ledgers.get(&(partner, handler.our_node_id))
            .map(|l| l.read().unwrap().tail_hash())
            .unwrap();
        drop(ledgers);

        // Tail hash should be valid
        let is_valid = handler.validate_ledger_hash_for_reserves(&partner, &tail_hash);
        assert!(is_valid, "Tail hash should be valid");
    }

    #[test]
    fn test_find_partner_for_deposit_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(90);
        let deposit = create_test_pubkey(91);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit);

        let found_partner = handler.find_partner_for_deposit(deposit);
        assert!(found_partner.is_some());
        assert_eq!(found_partner.unwrap(), partner);
    }

    #[test]
    fn test_get_next_sequence_number_for_deposit() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(100);
        let deposit = create_test_pubkey(101);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit);

        let result = handler.get_next_sequence_number_for_deposit(deposit);
        assert!(result.is_ok());
        let (sequence, found_partner) = result.unwrap();
        assert_eq!(sequence, 0); // New ledger has 0 updates
        assert_eq!(found_partner, partner);
    }

    #[test]
    fn test_get_next_sequence_number_not_found() {
        let handler = create_test_handler();
        let deposit = create_test_pubkey(102);

        let result = handler.get_next_sequence_number_for_deposit(deposit);
        assert!(result.is_err());
    }

    #[test]
    fn test_drop_all_ledgers_with_ledgers() {
        let handler = create_test_handler();
        let partner1 = create_test_pubkey(110);
        let partner2 = create_test_pubkey(111);

        add_operator_ledger(&handler, partner1);
        add_operator_ledger(&handler, partner2);

        let count = handler.drop_all_ledgers();
        assert_eq!(count, 2);

        let ledgers = handler.list_operator_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_close_ledger_trait_method() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(120);

        add_operator_ledger(&handler, partner);

        // Use trait method explicitly (core.rs has a different implementation)
        let result = <DepositsHandler<_> as LedgerOperationsExt>::close_ledger(&handler, partner);
        assert!(result.is_ok());

        let ledgers = handler.list_operator_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_close_ledger_trait_method_as_partner() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(130);

        add_partner_ledger_test(&handler, operator);

        // Use trait method explicitly (core.rs has a different implementation)
        let result = <DepositsHandler<_> as LedgerOperationsExt>::close_ledger(&handler, operator);
        assert!(result.is_ok());

        let ledgers = handler.list_partner_ledgers();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_get_all_ledgers_with_ledgers() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(140);

        add_operator_ledger(&handler, partner);

        let ledgers = handler.get_all_ledgers();
        assert_eq!(ledgers.len(), 1);
    }

    #[test]
    fn test_get_partner_ledger_found() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(150);

        add_partner_ledger_test(&handler, operator);

        let ledger = handler.get_partner_ledger(&operator);
        assert!(ledger.is_some());
    }

    #[test]
    fn test_get_all_ledger_updates_with_ledgers() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(160);

        add_operator_ledger(&handler, partner);

        let updates = handler.get_all_ledger_updates();
        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn test_get_all_audit_ledger_updates() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(170);

        add_operator_ledger(&handler, partner);

        let updates = handler.get_all_audit_ledger_updates();
        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn test_get_all_partner_ledger_updates() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(180);

        add_partner_ledger_test(&handler, operator);

        let updates = handler.get_all_partner_ledger_updates();
        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn test_get_ledger_hashes_with_both() {
        let handler = create_test_handler();
        let counterparty = create_test_pubkey(190);

        // Add ledger where we are operator
        add_operator_ledger(&handler, counterparty);
        // Add ledger where counterparty is operator
        add_partner_ledger_test(&handler, counterparty);

        let (local, remote) = handler.get_ledger_hashes(counterparty);
        assert!(local.is_some());
        assert!(remote.is_some());
    }

    #[test]
    fn test_get_committed_ledger_hashes_no_channel_manager() {
        let handler = create_test_handler();
        let counterparty = create_test_pubkey(200);

        // No channel manager set - should return (None, None)
        let (local, remote) = handler.get_committed_ledger_hashes_from_channel(counterparty);
        assert!(local.is_none());
        assert!(remote.is_none());
    }

    #[test]
    fn test_mark_ledger_committed() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(210);

        add_operator_ledger(&handler, partner);

        let result = handler.mark_ledger_committed(partner, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mark_ledger_committed_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(211);

        let result = handler.mark_ledger_committed(partner, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_ledger_hash_for_commitment_trait_method() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(220);

        add_operator_ledger(&handler, partner);

        // Use trait method explicitly - returns Some(hash) always when ledger exists
        let result = <DepositsHandler<_> as LedgerOperationsExt>::get_ledger_hash_for_commitment(
            &handler,
            partner
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_get_ledger_hash_for_commitment_trait_method_not_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(221);

        // Use trait method explicitly - returns Ok(None) when ledger doesn't exist
        let result = <DepositsHandler<_> as LedgerOperationsExt>::get_ledger_hash_for_commitment(
            &handler,
            partner
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_all_signed_audit_updates_empty() {
        let handler = create_test_handler();

        let updates = handler.get_all_signed_audit_updates();
        assert!(updates.is_empty());
    }

    #[test]
    fn test_get_ledger_address_as_partner() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(230);

        add_partner_ledger_test(&handler, operator);

        let result = handler.get_ledger_address(operator);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "tb1qtest_partner");
    }

    #[test]
    fn test_get_ledger_updates_as_partner() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(240);

        add_partner_ledger_test(&handler, operator);

        let result = handler.get_ledger_updates(operator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_ledger_sync_state_as_partner() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(250);

        add_partner_ledger_test(&handler, operator);

        let result = handler.get_ledger_sync_state(operator);
        assert!(result.is_ok());
    }
}
