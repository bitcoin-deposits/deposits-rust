//! Deposit Operations for Bitcoin Deposits
//!
//! This module delegates deposit query operations to the core Handler.
//! Both DepositsHandler and core Handler share the same ledger storage,
//! so delegation produces identical results while centralizing the logic.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use deposits_core::DepositsError;
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export trait from deposits-core for backwards compatibility
pub use deposits_core::handler_traits::DepositOperations;

impl<L: Deref + Clone + Send + Sync> DepositOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn list_deposits(&self) -> Result<Vec<PublicKey>, DepositsError> {
        // Delegate to core_handler (shares same ledgers)
        if let Some(ref handler) = self.core_handler {
            return handler.list_deposits();
        }
        // Fallback: direct implementation for when core_handler isn't initialized
        let mut all_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for deposit in ledger.state.deposits.values() {
                all_deposits.push(deposit.pubkey);
            }
        }
        Ok(all_deposits)
    }

    fn list_deposits_for_depositor(
        &self,
        depositor_pubkey: PublicKey,
    ) -> Result<Vec<PublicKey>, DepositsError> {
        if let Some(ref handler) = self.core_handler {
            return handler.list_deposits_for_depositor(depositor_pubkey);
        }
        let mut depositor_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&depositor_pubkey) {
                depositor_deposits.push(deposit.pubkey);
            }
        }
        Ok(depositor_deposits)
    }

    fn list_deposits_for_pubkey(
        &self,
        deposit_pubkey: PublicKey,
    ) -> Result<Vec<PublicKey>, DepositsError> {
        if let Some(ref handler) = self.core_handler {
            return handler.list_deposits_for_pubkey(deposit_pubkey);
        }
        let mut matching_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for deposit in ledger.state.deposits.values() {
                if deposit.pubkey == deposit_pubkey {
                    matching_deposits.push(deposit.pubkey);
                }
            }
        }
        Ok(matching_deposits)
    }

    fn get_deposit_balance(&self, deposit_pubkey: PublicKey) -> Result<u64, DepositsError> {
        if let Some(ref handler) = self.core_handler {
            return handler.get_deposit_balance(deposit_pubkey);
        }
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&deposit_pubkey) {
                return Ok(deposit.balance.saturating_sub(deposit.locked_balance));
            }
        }
        Err(DepositsError::DepositNotFound)
    }

    fn find_deposit_by_payment_hash(&self, payment_hash: &[u8; 32]) -> Option<(PublicKey, PublicKey, u64)> {
        if let Some(ref handler) = self.core_handler {
            return handler.find_deposit_by_payment_hash(payment_hash);
        }
        let ledgers = self.ledgers.lock().unwrap();
        for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
            if *operator_id == self.our_node_id {
                let ledger = ledger_arc.read().unwrap();
                for (deposit_pubkey, deposit) in ledger.state.deposits.iter() {
                    for invoice in &deposit.invoices {
                        if &invoice.payment_hash == payment_hash {
                            return Some((*partner_id, *deposit_pubkey, invoice.amount));
                        }
                    }
                }
            }
        }
        None
    }

    fn get_active_depositors(&self) -> Vec<PublicKey> {
        if let Some(ref handler) = self.core_handler {
            return handler.get_active_depositors();
        }
        let mut active_depositors = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for (depositor_pubkey, deposit) in &ledger.state.deposits {
                if deposit.balance > 0 {
                    active_depositors.push(*depositor_pubkey);
                }
            }
        }
        active_depositors
    }

    fn get_total_deposit_balances(&self, partner_node_id: PublicKey) -> Option<u64> {
        if let Some(ref handler) = self.core_handler {
            return handler.get_total_deposit_balances(partner_node_id);
        }
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            let total = ledger.state.deposits.values()
                .map(|deposit| deposit.balance)
                .sum();
            Some(total)
        } else {
            None
        }
    }

    fn get_deposits_for_partner(&self, partner_node_id: PublicKey) -> Option<Vec<(PublicKey, u64, u64)>> {
        if let Some(ref handler) = self.core_handler {
            return handler.get_deposits_for_partner(partner_node_id);
        }
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            let deposits: Vec<(PublicKey, u64, u64)> = ledger.state.deposits.iter()
                .map(|(depositor_pubkey, deposit)| (*depositor_pubkey, deposit.balance, deposit.locked_balance))
                .collect();
            Some(deposits)
        } else {
            None
        }
    }

    fn get_max_outstanding_invoice_amount(&self, partner_node_id: PublicKey) -> Option<u64> {
        if let Some(ref handler) = self.core_handler {
            return handler.get_max_outstanding_invoice_amount(partner_node_id);
        }
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            let max_amount = ledger.state.deposits.values()
                .flat_map(|deposit| &deposit.invoices)
                .filter(|invoice| {
                    use deposits_core::time_utils::is_expired;
                    !is_expired(invoice.expires)
                })
                .map(|invoice| invoice.amount)
                .max()
                .unwrap_or(0);
            Some(max_amount)
        } else {
            None
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
    fn test_list_deposits_empty() {
        let handler = create_test_handler();
        let deposits = handler.list_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_list_deposits_for_depositor_empty() {
        let handler = create_test_handler();
        let depositor = create_test_pubkey(1);
        let deposits = handler.list_deposits_for_depositor(depositor).unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_list_deposits_for_pubkey_empty() {
        let handler = create_test_handler();
        let deposit = create_test_pubkey(2);
        let deposits = handler.list_deposits_for_pubkey(deposit).unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_get_deposit_balance_not_found() {
        let handler = create_test_handler();
        let deposit = create_test_pubkey(3);
        let result = handler.get_deposit_balance(deposit);
        assert!(matches!(result, Err(DepositsError::DepositNotFound)));
    }

    #[test]
    fn test_find_deposit_by_payment_hash_not_found() {
        let handler = create_test_handler();
        let payment_hash = [0xAB; 32];
        let result = handler.find_deposit_by_payment_hash(&payment_hash);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_active_depositors_empty() {
        let handler = create_test_handler();
        let depositors = handler.get_active_depositors();
        assert!(depositors.is_empty());
    }

    #[test]
    fn test_get_total_deposit_balances_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(4);
        let total = handler.get_total_deposit_balances(partner);
        assert!(total.is_none());
    }

    #[test]
    fn test_get_deposits_for_partner_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(5);
        let deposits = handler.get_deposits_for_partner(partner);
        assert!(deposits.is_none());
    }

    #[test]
    fn test_get_max_outstanding_invoice_no_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(6);
        let max = handler.get_max_outstanding_invoice_amount(partner);
        assert!(max.is_none());
    }

    use deposits_core::Ledger;
    use deposits_core::{Deposit, FeeStructure, Invoice};
    use std::sync::RwLock;

    /// Helper to add an operator ledger (where handler's node is operator)
    fn add_operator_ledger(handler: &DepositsHandler<Arc<TestLogger>>, partner: PublicKey) {
        let ledger = Ledger::new_as_operator(
            handler.our_node_id,
            partner,
            "tb1qtest".to_string(),
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

    /// Helper to add an invoice to a deposit
    fn add_invoice_to_deposit(
        handler: &DepositsHandler<Arc<TestLogger>>,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        payment_hash: [u8; 32],
        amount: u64,
        expires: u64,
    ) {
        let ledgers = handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, partner)) {
            let mut ledger = ledger_arc.write().unwrap();
            if let Some(deposit) = ledger.state.deposits.get_mut(&deposit_pubkey) {
                let invoice: deposits_core::Invoice = deposits_core::Invoice {
                    id: "test-invoice".to_string(),
                    payment_hash,
                    amount,
                    expires,
                    assigned_deposit: deposit_pubkey,
                    bolt11: "lntb1test".to_string(),
                };
                deposit.invoices.push(invoice);
            }
        }
    }

    #[test]
    fn test_list_deposits_with_deposits() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(10);
        let deposit1 = create_test_pubkey(11);
        let deposit2 = create_test_pubkey(12);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, partner, deposit2, 200_000, 0);

        let deposits = handler.list_deposits().unwrap();
        assert_eq!(deposits.len(), 2);
        assert!(deposits.contains(&deposit1));
        assert!(deposits.contains(&deposit2));
    }

    #[test]
    fn test_list_deposits_for_depositor_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(20);
        let depositor = create_test_pubkey(21);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, depositor, 100_000, 0);

        let deposits = handler.list_deposits_for_depositor(depositor).unwrap();
        assert_eq!(deposits.len(), 1);
        assert!(deposits.contains(&depositor));
    }

    #[test]
    fn test_list_deposits_for_pubkey_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(30);
        let deposit = create_test_pubkey(31);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);

        let deposits = handler.list_deposits_for_pubkey(deposit).unwrap();
        assert_eq!(deposits.len(), 1);
        assert!(deposits.contains(&deposit));
    }

    #[test]
    fn test_get_deposit_balance_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(40);
        let deposit = create_test_pubkey(41);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);

        let balance = handler.get_deposit_balance(deposit).unwrap();
        assert_eq!(balance, 100_000);
    }

    #[test]
    fn test_get_deposit_balance_with_locked() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(50);
        let deposit = create_test_pubkey(51);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 30_000);

        let balance = handler.get_deposit_balance(deposit).unwrap();
        assert_eq!(balance, 70_000); // 100_000 - 30_000
    }

    #[test]
    fn test_find_deposit_by_payment_hash_found() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(60);
        let deposit = create_test_pubkey(61);
        let payment_hash = [0xAB; 32];

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);
        // Use a far-future expiration so invoice isn't expired
        add_invoice_to_deposit(&handler, partner, deposit, payment_hash, 50_000, u64::MAX);

        let result = handler.find_deposit_by_payment_hash(&payment_hash);
        assert!(result.is_some());
        let (found_partner, found_deposit, amount) = result.unwrap();
        assert_eq!(found_partner, partner);
        assert_eq!(found_deposit, deposit);
        assert_eq!(amount, 50_000);
    }

    #[test]
    fn test_get_active_depositors_with_deposits() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(70);
        let deposit1 = create_test_pubkey(71);
        let deposit2 = create_test_pubkey(72);
        let deposit3 = create_test_pubkey(73);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit1, 100_000, 0); // active
        add_deposit_to_ledger(&handler, partner, deposit2, 0, 0);       // zero balance
        add_deposit_to_ledger(&handler, partner, deposit3, 50_000, 0);  // active

        let depositors = handler.get_active_depositors();
        assert_eq!(depositors.len(), 2);
        assert!(depositors.contains(&deposit1));
        assert!(!depositors.contains(&deposit2)); // zero balance
        assert!(depositors.contains(&deposit3));
    }

    #[test]
    fn test_get_total_deposit_balances_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(80);
        let deposit1 = create_test_pubkey(81);
        let deposit2 = create_test_pubkey(82);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, partner, deposit2, 200_000, 0);

        let total = handler.get_total_deposit_balances(partner);
        assert!(total.is_some());
        assert_eq!(total.unwrap(), 300_000);
    }

    #[test]
    fn test_get_deposits_for_partner_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(90);
        let deposit1 = create_test_pubkey(91);
        let deposit2 = create_test_pubkey(92);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit1, 100_000, 10_000);
        add_deposit_to_ledger(&handler, partner, deposit2, 200_000, 50_000);

        let deposits = handler.get_deposits_for_partner(partner);
        assert!(deposits.is_some());
        let deposits = deposits.unwrap();
        assert_eq!(deposits.len(), 2);

        // Check deposit details
        for (pubkey, balance, locked) in &deposits {
            if *pubkey == deposit1 {
                assert_eq!(*balance, 100_000);
                assert_eq!(*locked, 10_000);
            } else if *pubkey == deposit2 {
                assert_eq!(*balance, 200_000);
                assert_eq!(*locked, 50_000);
            }
        }
    }

    #[test]
    fn test_get_max_outstanding_invoice_with_invoices() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(100);
        let deposit = create_test_pubkey(101);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);
        // Add multiple invoices with far-future expiration
        add_invoice_to_deposit(&handler, partner, deposit, [0x01; 32], 50_000, u64::MAX);

        // Need to add more invoices differently since our helper replaces
        {
            let ledgers = handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, partner)) {
                let mut ledger = ledger_arc.write().unwrap();
                if let Some(dep) = ledger.state.deposits.get_mut(&deposit) {
                    let invoice2: deposits_core::Invoice = deposits_core::Invoice {
                        id: "test-invoice-2".to_string(),
                        payment_hash: [0x02; 32],
                        amount: 100_000,
                        expires: u64::MAX,
                        assigned_deposit: deposit,
                        bolt11: "lntb2test".to_string(),
                    };
                    dep.invoices.push(invoice2);
                    let invoice3: deposits_core::Invoice = deposits_core::Invoice {
                        id: "test-invoice-3".to_string(),
                        payment_hash: [0x03; 32],
                        amount: 75_000,
                        expires: u64::MAX,
                        assigned_deposit: deposit,
                        bolt11: "lntb3test".to_string(),
                    };
                    dep.invoices.push(invoice3);
                }
            }
        }

        let max = handler.get_max_outstanding_invoice_amount(partner);
        assert!(max.is_some());
        assert_eq!(max.unwrap(), 100_000); // Max of 50k, 100k, 75k
    }

    #[test]
    fn test_get_max_outstanding_invoice_empty() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(110);
        let deposit = create_test_pubkey(111);

        add_operator_ledger(&handler, partner);
        add_deposit_to_ledger(&handler, partner, deposit, 100_000, 0);
        // No invoices added

        let max = handler.get_max_outstanding_invoice_amount(partner);
        assert!(max.is_some());
        assert_eq!(max.unwrap(), 0); // No invoices means max is 0
    }

    #[test]
    fn test_list_deposits_multiple_ledgers() {
        let handler = create_test_handler();
        let partner1 = create_test_pubkey(120);
        let partner2 = create_test_pubkey(121);
        let deposit1 = create_test_pubkey(122);
        let deposit2 = create_test_pubkey(123);

        add_operator_ledger(&handler, partner1);
        add_operator_ledger(&handler, partner2);
        add_deposit_to_ledger(&handler, partner1, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, partner2, deposit2, 200_000, 0);

        let deposits = handler.list_deposits().unwrap();
        assert_eq!(deposits.len(), 2);
        assert!(deposits.contains(&deposit1));
        assert!(deposits.contains(&deposit2));
    }
}
