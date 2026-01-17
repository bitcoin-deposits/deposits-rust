//! Reserves Operations for Bitcoin Deposits
//!
//! This module provides reserves query operations including
//! status checking and amount lookups.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use deposits_core::DepositsError;
use deposits_core::LedgerValidator;
use deposits_core::ReservesStatus;
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export trait from deposits-core with backwards-compatible name
// (deposits-core uses ReservesQueryOps to avoid conflict with the adapter trait)
pub use deposits_core::handler_traits::ReservesQueryOps as ReservesOperations;

impl<L: Deref + Clone> ReservesOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_channel_reserves_status(&self, partner_node_id: PublicKey) -> Result<ReservesStatus, DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();

            let total_deposit_balances = LedgerValidator::total_balance(&ledger);
            let required_amount = LedgerValidator::calculate_minimum_reserves(&ledger);
            let current_amount = ledger.reserves_amount();
            let excess_amount = if current_amount > required_amount {
                current_amount - required_amount
            } else {
                0
            };

            let max_outstanding_invoice = 0; // TODO: Track properly
            let deposit_count = ledger.state.deposits.len();
            let total_locked_balances = ledger.state.deposits.values()
                .map(|d| d.locked_balance)
                .sum();

            Ok(ReservesStatus {
                current_amount,
                required_amount,
                excess_amount,
                total_deposit_balances,
                max_outstanding_invoice,
                deposit_count,
                total_locked_balances,
            })
        } else {
            Err(DepositsError::DepositNotFound)
        }
    }

    fn get_channel_reserves_amount(&self, partner_node_id: PublicKey) -> Option<u64> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            Some(ledger.reserves_amount())
        } else {
            None
        }
    }

    fn get_commitment_tx_reserves_amount(&self, operator_node_id: PublicKey) -> Option<u64> {
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&operator_node_id);
            if let Some(channel) = channels.first() {
                return cm.get_channel_remote_reserves_amount(&operator_node_id, &channel.channel_id);
            }
        }
        None
    }

    fn get_channel_reserves(&self, counterparty_node_id: PublicKey) -> (Option<u64>, Option<u64>) {
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&counterparty_node_id);
            if let Some(channel) = channels.first() {
                let local = cm.get_channel_local_reserves_amount(&counterparty_node_id, &channel.channel_id);
                let remote = cm.get_channel_remote_reserves_amount(&counterparty_node_id, &channel.channel_id);
                return (local, remote);
            }
        }
        (None, None)
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
    fn test_get_channel_reserves_status_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(1);

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_channel_reserves_amount_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(2);

        let amount = handler.get_channel_reserves_amount(partner);
        assert!(amount.is_none());
    }

    #[test]
    fn test_get_commitment_tx_reserves_no_channel() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(3);

        let amount = handler.get_commitment_tx_reserves_amount(operator);
        assert!(amount.is_none());
    }

    #[test]
    fn test_get_channel_reserves_no_channel() {
        let handler = create_test_handler();
        let counterparty = create_test_pubkey(4);

        let (local, remote) = handler.get_channel_reserves(counterparty);
        assert!(local.is_none());
        assert!(remote.is_none());
    }

    use deposits_core::Ledger;
    use deposits_core::{Deposit, FeeStructure};
    use std::sync::RwLock;

    /// Helper to add an operator ledger with optional reserves
    fn add_operator_ledger_with_reserves(
        handler: &DepositsHandler<Arc<TestLogger>>,
        partner: PublicKey,
        reserves_amount: u64,
    ) {
        let mut ledger = Ledger::new_as_operator(
            handler.our_node_id,
            partner,
            "tb1qtest".to_string(),
        );
        // Set reserves via ReservesOutput
        ledger.state.reserves = deposits_core::types::ReservesOutput::new(
            [0u8; 32],
            reserves_amount,
            handler.our_node_id,
        );
        handler.ledgers.lock().unwrap().insert(
            (handler.our_node_id, partner),
            Arc::new(RwLock::new(ledger))
        );
    }

    /// Helper to add a deposit to a ledger
    fn add_deposit_to_ledger(
        handler: &DepositsHandler<Arc<TestLogger>>,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        balance: u64,
        locked_balance: u64,
    ) {
        let ledgers = handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, partner)) {
            let mut ledger = ledger_arc.write().unwrap();
            // Use deposits-core Deposit type
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = balance;
            deposit.locked_balance = locked_balance;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
        }
    }

    #[test]
    fn test_get_channel_reserves_status_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(10);

        add_operator_ledger_with_reserves(&handler, partner, 100_000);

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.current_amount, 100_000);
        assert_eq!(status.deposit_count, 0);
        assert_eq!(status.total_locked_balances, 0);
    }

    #[test]
    fn test_get_channel_reserves_status_with_deposits() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(20);
        let deposit1 = create_test_pubkey(21);
        let deposit2 = create_test_pubkey(22);

        add_operator_ledger_with_reserves(&handler, partner, 500_000);
        add_deposit_to_ledger(&handler, partner, deposit1, 100_000, 10_000);
        add_deposit_to_ledger(&handler, partner, deposit2, 200_000, 50_000);

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.current_amount, 500_000);
        assert_eq!(status.deposit_count, 2);
        assert_eq!(status.total_deposit_balances, 300_000); // 100k + 200k
        assert_eq!(status.total_locked_balances, 60_000);   // 10k + 50k
    }

    #[test]
    fn test_get_channel_reserves_status_excess_amount() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(30);
        let deposit = create_test_pubkey(31);

        // High reserves, low deposit balance
        add_operator_ledger_with_reserves(&handler, partner, 1_000_000);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.current_amount, 1_000_000);
        // Excess should be current - required (required depends on deposit balances)
        assert!(status.excess_amount > 0 || status.current_amount >= status.required_amount);
    }

    #[test]
    fn test_get_channel_reserves_amount_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(40);

        add_operator_ledger_with_reserves(&handler, partner, 250_000);

        let amount = handler.get_channel_reserves_amount(partner);
        assert!(amount.is_some());
        assert_eq!(amount.unwrap(), 250_000);
    }

    #[test]
    fn test_get_channel_reserves_status_empty_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(50);

        // Ledger with 0 reserves and no deposits
        add_operator_ledger_with_reserves(&handler, partner, 0);

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.current_amount, 0);
        assert_eq!(status.required_amount, 0);
        assert_eq!(status.excess_amount, 0);
        assert_eq!(status.deposit_count, 0);
        assert_eq!(status.total_deposit_balances, 0);
        assert_eq!(status.total_locked_balances, 0);
    }

    #[test]
    fn test_get_channel_reserves_amount_zero() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(60);

        add_operator_ledger_with_reserves(&handler, partner, 0);

        let amount = handler.get_channel_reserves_amount(partner);
        assert!(amount.is_some());
        assert_eq!(amount.unwrap(), 0);
    }

    #[test]
    fn test_get_channel_reserves_status_multiple_deposits() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(70);

        add_operator_ledger_with_reserves(&handler, partner, 1_000_000);

        // Add many deposits
        for i in 0..5u8 {
            let deposit = create_test_pubkey(71 + i);
            add_deposit_to_ledger(&handler, partner, deposit, 100_000, 10_000);
        }

        let result = handler.get_channel_reserves_status(partner);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.deposit_count, 5);
        assert_eq!(status.total_deposit_balances, 500_000); // 5 * 100k
        assert_eq!(status.total_locked_balances, 50_000);   // 5 * 10k
    }
}
