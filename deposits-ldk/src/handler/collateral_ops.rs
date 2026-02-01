//! Collateral Operations for Bitcoin Deposits
//!
//! This module provides collateral query operations including
//! partner info and attestation lookups.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export trait from deposits-core for backwards compatibility
pub use deposits_core::handler_traits::CollateralOperations;
// Re-export types that were previously in core.rs
pub use deposits_core::handler_types::{CollateralInfo, QuorumMemberInfo};

impl<L: Deref + Clone + Send + Sync> CollateralOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_collateral_info(&self, partner_node_id: PublicKey) -> Option<CollateralInfo> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();

            let quorum_members: Vec<QuorumMemberInfo> = ledger.state.quorum_members.iter()
                .map(|reserves_id| {
                    let attestation = ledger.state.collateral_attestations.get(reserves_id);
                    QuorumMemberInfo {
                        pubkey: *reserves_id,
                        collateral_amount: attestation.map(|a| a.amount).unwrap_or(0),
                        block_height: attestation.map(|a| a.block_height).unwrap_or(0),
                        has_attestation: attestation.is_some(),
                    }
                })
                .collect();

            let member_attestation = ledger.state.collateral_attestations.get(&partner_node_id);
            let member_collateral = member_attestation.map(|a| QuorumMemberInfo {
                pubkey: partner_node_id,
                collateral_amount: a.amount,
                block_height: a.block_height,
                has_attestation: true,
            });

            Some(CollateralInfo {
                quorum_members,
                member_attestation: member_collateral,
                total_available_collateral: ledger.state.collateral_attestations.values()
                    .map(|a| a.available_collateral())
                    .sum(),
            })
        } else {
            None
        }
    }

    fn get_quorum_members(&self, partner_node_id: PublicKey) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            ledger.state.quorum_members.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    fn is_quorum_member(&self, partner_node_id: PublicKey, potential_collateral: PublicKey) -> bool {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            ledger.state.quorum_members.contains(&potential_collateral)
        } else {
            false
        }
    }

    fn get_total_available_collateral(&self, partner_node_id: PublicKey) -> u64 {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();

            // Sum of attestation collateral
            let attestation_collateral: u64 = ledger.state.collateral_attestations.values()
                .map(|a| a.available_collateral())
                .sum();

            // Sum of deposit locked collateral (with active locks)
            // Use block 0 as a simple check - in production this should be current block height
            // For now, count all locks with non-zero expiry
            let locked_collateral: u64 = ledger.state.deposits.values()
                .filter(|d| d.collateral_lock_expires > 0)
                .map(|d| d.collateral_lock_amount)
                .sum();

            attestation_collateral + locked_collateral
        } else {
            0
        }
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
    fn test_get_collateral_info_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(1);

        let info = handler.get_collateral_info(partner);
        assert!(info.is_none());
    }

    #[test]
    fn test_get_quorum_members_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(2);

        let partners = handler.get_quorum_members(partner);
        assert!(partners.is_empty());
    }

    #[test]
    fn test_is_quorum_member_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(3);
        let collateral = create_test_pubkey(4);

        let is_partner = handler.is_quorum_member(partner, collateral);
        assert!(!is_partner);
    }

    #[test]
    fn test_get_total_available_collateral_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(5);

        let total = handler.get_total_available_collateral(partner);
        assert_eq!(total, 0);
    }
}
