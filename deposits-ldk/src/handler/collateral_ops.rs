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
pub use deposits_core::handler_types::{CollateralInfo, CollateralPartnerInfo};

impl<L: Deref + Clone + Send + Sync> CollateralOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_collateral_info(&self, partner_node_id: PublicKey) -> Option<CollateralInfo> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();

            let collateral_partners: Vec<CollateralPartnerInfo> = ledger.state.collateral_partners.iter()
                .map(|reserves_id| {
                    let attestation = ledger.state.collateral_attestations.get(reserves_id);
                    CollateralPartnerInfo {
                        pubkey: *reserves_id,
                        collateral_amount: attestation.map(|a| a.amount).unwrap_or(0),
                        block_height: attestation.map(|a| a.block_height).unwrap_or(0),
                        has_attestation: attestation.is_some(),
                    }
                })
                .collect();

            let partner_attestation = ledger.state.collateral_attestations.get(&partner_node_id);
            let partner_collateral = partner_attestation.map(|a| CollateralPartnerInfo {
                pubkey: partner_node_id,
                collateral_amount: a.amount,
                block_height: a.block_height,
                has_attestation: true,
            });

            Some(CollateralInfo {
                collateral_partners,
                partner_attestation: partner_collateral,
                total_available_collateral: ledger.state.collateral_attestations.values()
                    .map(|a| a.available_collateral())
                    .sum(),
            })
        } else {
            None
        }
    }

    fn get_collateral_partners(&self, partner_node_id: PublicKey) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            ledger.state.collateral_partners.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    fn is_collateral_partner(&self, partner_node_id: PublicKey, potential_collateral: PublicKey) -> bool {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            ledger.state.collateral_partners.contains(&potential_collateral)
        } else {
            false
        }
    }

    fn get_total_available_collateral(&self, partner_node_id: PublicKey) -> u64 {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            ledger.state.collateral_attestations.values()
                .map(|a| a.available_collateral())
                .sum()
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
    fn test_get_collateral_partners_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(2);

        let partners = handler.get_collateral_partners(partner);
        assert!(partners.is_empty());
    }

    #[test]
    fn test_is_collateral_partner_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(3);
        let collateral = create_test_pubkey(4);

        let is_partner = handler.is_collateral_partner(partner, collateral);
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
