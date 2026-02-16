//! Deposit Operations for Bitcoin Deposits
//!
//! This module delegates deposit query operations to the core Handler.
//! Both DepositsHandler and core Handler share the same ledger storage,
//! so delegation produces identical results while centralizing the logic.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use deposits_core::DepositsError;
use deposits_core::types::DepositId;
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export trait from deposits-core for backwards compatibility
pub use deposits_core::handler_traits::DepositOperations;

impl<L: Deref + Clone + Send + Sync> DepositOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn list_deposits(&self) -> Result<Vec<DepositId>, DepositsError> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .list_deposits()
    }

    fn list_deposits_for_deposit_id(
        &self,
        deposit_id: DepositId,
    ) -> Result<Vec<DepositId>, DepositsError> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .list_deposits_for_deposit_id(deposit_id)
    }

    fn get_deposit_balance(&self, deposit_id: DepositId) -> Result<u64, DepositsError> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_deposit_balance(deposit_id)
    }

    fn get_deposit_descriptor(&self, deposit_id: DepositId) -> Result<String, DepositsError> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_deposit_descriptor(deposit_id)
    }

    fn find_deposit_by_payment_hash(&self, payment_hash: &[u8; 32]) -> std::option::Option<(std::string::String, DepositId, u64)> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .find_deposit_by_payment_hash(payment_hash)
    }

    fn get_active_depositors(&self) -> Vec<DepositId> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_active_depositors()
    }

    fn get_total_deposit_balances(&self, partner_node_id: PublicKey) -> Option<u64> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_total_deposit_balances(partner_node_id)
    }

    fn get_deposits_for_partner(&self, partner_node_id: PublicKey) -> Option<Vec<(DepositId, u64, u64)>> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_deposits_for_partner(partner_node_id)
    }

    fn get_max_outstanding_invoice_amount(&self, partner_node_id: PublicKey) -> Option<u64> {
        self.core_handler
            .as_ref()
            .expect("core_handler must be initialized")
            .get_max_outstanding_invoice_amount(partner_node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;
    use deposits_core::types::compute_deposit_id;

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

    fn create_test_deposit_id(seed: u8) -> DepositId {
        let pubkey = create_test_pubkey(seed);
        let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
        compute_deposit_id(&descriptor)
    }

    #[test]
    fn test_list_deposits_empty() {
        let handler = create_test_handler();
        let deposits = handler.list_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_list_deposits_for_deposit_id_empty() {
        let handler = create_test_handler();
        let deposit_id = create_test_deposit_id(1);
        let deposits = handler.list_deposits_for_deposit_id(deposit_id).unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_get_deposit_balance_not_found() {
        let handler = create_test_handler();
        let deposit_id = create_test_deposit_id(3);
        let result = handler.get_deposit_balance(deposit_id);
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
    use std::sync::RwLock;

    /// Helper to add an operator ledger (where handler's node is operator)
    fn add_operator_ledger(handler: &DepositsHandler<Arc<TestLogger>>, reserves_id: &str) {
        let ledger = Ledger::new_as_operator(
            handler.our_node_id,
            reserves_id.to_string(),
            "tb1qtest".to_string(),
            0,
        );
        handler.ledgers.lock().unwrap().insert(
            (handler.our_node_id, reserves_id.to_string()),
            Arc::new(RwLock::new(ledger))
        );
    }

    /// Helper to add a deposit to a ledger using DepositId
    fn add_deposit_to_ledger(
        handler: &DepositsHandler<Arc<TestLogger>>,
        reserves_id: &str,
        deposit_id: DepositId,
        balance: u64,
        locked_balance: u64,
    ) {
        let ledgers = handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, reserves_id.to_string())) {
            let mut ledger = ledger_arc.write().unwrap();
            // Create a descriptor that produces the given deposit_id
            // Note: In tests, we just need the deposit_id to match, so we create a placeholder descriptor
            // and override the deposit_id field
            let descriptor = format!("test_descriptor_{}", hex::encode(&deposit_id));
            let mut deposit = deposits_core::Deposit::new(descriptor, None);
            // Override the deposit_id to match the test expectation
            deposit.deposit_id = deposit_id;
            deposit.balance = balance;
            deposit.locked_balance = locked_balance;
            ledger.state.deposits.insert(deposit_id, deposit);
        }
    }

    /// Helper to add an invoice to a deposit
    fn add_invoice_to_deposit(
        handler: &DepositsHandler<Arc<TestLogger>>,
        reserves_id: &str,
        deposit_id: DepositId,
        payment_hash: [u8; 32],
        amount: u64,
        expires: u64,
    ) {
        let ledgers = handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, reserves_id.to_string())) {
            let mut ledger = ledger_arc.write().unwrap();
            if let Some(deposit) = ledger.state.deposits.get_mut(&deposit_id) {
                let invoice = deposits_core::Invoice {
                    id: "test-invoice".to_string(),
                    payment_hash,
                    amount,
                    expires,
                    assigned_deposit: deposit_id,
                    bolt11: "lntb1test".to_string(),
                };
                deposit.invoices.push(invoice);
            }
        }
    }

    #[test]
    fn test_list_deposits_with_deposits() {
        let handler = create_test_handler();
        let reserves_id = "reserves-10";
        let deposit1 = create_test_deposit_id(11);
        let deposit2 = create_test_deposit_id(12);

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, reserves_id, deposit2, 200_000, 0);

        let deposits = handler.list_deposits().unwrap();
        assert_eq!(deposits.len(), 2);
        assert!(deposits.contains(&deposit1));
        assert!(deposits.contains(&deposit2));
    }

    #[test]
    fn test_list_deposits_for_deposit_id_found() {
        let handler = create_test_handler();
        let reserves_id = "reserves-20";
        let deposit_id = create_test_deposit_id(21);

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit_id, 100_000, 0);

        let deposits = handler.list_deposits_for_deposit_id(deposit_id).unwrap();
        assert_eq!(deposits.len(), 1);
        assert!(deposits.contains(&deposit_id));
    }

    #[test]
    fn test_get_deposit_balance_found() {
        let handler = create_test_handler();
        let reserves_id = "reserves-40";
        let deposit_id = create_test_deposit_id(41);

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit_id, 100_000, 0);

        let balance = handler.get_deposit_balance(deposit_id).unwrap();
        assert_eq!(balance, 100_000);
    }

    #[test]
    fn test_get_deposit_balance_with_locked() {
        let handler = create_test_handler();
        let reserves_id = "reserves-50";
        let deposit_id = create_test_deposit_id(51);

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit_id, 100_000, 30_000);

        let balance = handler.get_deposit_balance(deposit_id).unwrap();
        assert_eq!(balance, 70_000); // 100_000 - 30_000
    }

    #[test]
    fn test_find_deposit_by_payment_hash_found() {
        let handler = create_test_handler();
        let reserves_id = "reserves-60";
        let deposit_id = create_test_deposit_id(61);
        let payment_hash = [0xAB; 32];

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit_id, 100_000, 0);
        add_invoice_to_deposit(&handler, reserves_id, deposit_id, payment_hash, 50_000, u64::MAX);

        let result = handler.find_deposit_by_payment_hash(&payment_hash);
        assert!(result.is_some());
        let (found_reserves_id, found_deposit_id, amount) = result.unwrap();
        assert_eq!(found_reserves_id, reserves_id);
        assert_eq!(found_deposit_id, deposit_id);
        assert_eq!(amount, 50_000);
    }

    #[test]
    fn test_get_active_depositors_with_deposits() {
        let handler = create_test_handler();
        let reserves_id = "reserves-70";
        let deposit1 = create_test_deposit_id(71);
        let deposit2 = create_test_deposit_id(72);
        let deposit3 = create_test_deposit_id(73);

        add_operator_ledger(&handler, reserves_id);
        add_deposit_to_ledger(&handler, reserves_id, deposit1, 100_000, 0); // active
        add_deposit_to_ledger(&handler, reserves_id, deposit2, 0, 0);       // zero balance
        add_deposit_to_ledger(&handler, reserves_id, deposit3, 50_000, 0);  // active

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
        let reserves_id = partner.to_string();
        let deposit1 = create_test_deposit_id(81);
        let deposit2 = create_test_deposit_id(82);

        add_operator_ledger(&handler, &reserves_id);
        add_deposit_to_ledger(&handler, &reserves_id, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, &reserves_id, deposit2, 200_000, 0);

        let total = handler.get_total_deposit_balances(partner);
        assert!(total.is_some());
        assert_eq!(total.unwrap(), 300_000);
    }

    #[test]
    fn test_get_deposits_for_partner_with_ledger() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(90);
        let reserves_id = partner.to_string();
        let deposit1 = create_test_deposit_id(91);
        let deposit2 = create_test_deposit_id(92);

        add_operator_ledger(&handler, &reserves_id);
        add_deposit_to_ledger(&handler, &reserves_id, deposit1, 100_000, 10_000);
        add_deposit_to_ledger(&handler, &reserves_id, deposit2, 200_000, 50_000);

        let deposits = handler.get_deposits_for_partner(partner);
        assert!(deposits.is_some());
        let deposits = deposits.unwrap();
        assert_eq!(deposits.len(), 2);

        for (dep_id, balance, locked) in &deposits {
            if *dep_id == deposit1 {
                assert_eq!(*balance, 100_000);
                assert_eq!(*locked, 10_000);
            } else if *dep_id == deposit2 {
                assert_eq!(*balance, 200_000);
                assert_eq!(*locked, 50_000);
            }
        }
    }

    #[test]
    fn test_get_max_outstanding_invoice_with_invoices() {
        let handler = create_test_handler();
        let partner = create_test_pubkey(100);
        let reserves_id = partner.to_string();
        let deposit_id = create_test_deposit_id(101);

        add_operator_ledger(&handler, &reserves_id);
        add_deposit_to_ledger(&handler, &reserves_id, deposit_id, 100_000, 0);
        add_invoice_to_deposit(&handler, &reserves_id, deposit_id, [0x01; 32], 50_000, u64::MAX);

        {
            let ledgers = handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(handler.our_node_id, reserves_id.clone())) {
                let mut ledger = ledger_arc.write().unwrap();
                if let Some(dep) = ledger.state.deposits.get_mut(&deposit_id) {
                    let invoice2 = deposits_core::Invoice {
                        id: "test-invoice-2".to_string(),
                        payment_hash: [0x02; 32],
                        amount: 100_000,
                        expires: u64::MAX,
                        assigned_deposit: deposit_id,
                        bolt11: "lntb2test".to_string(),
                    };
                    dep.invoices.push(invoice2);
                    let invoice3 = deposits_core::Invoice {
                        id: "test-invoice-3".to_string(),
                        payment_hash: [0x03; 32],
                        amount: 75_000,
                        expires: u64::MAX,
                        assigned_deposit: deposit_id,
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
        let reserves_id = partner.to_string();
        let deposit_id = create_test_deposit_id(111);

        add_operator_ledger(&handler, &reserves_id);
        add_deposit_to_ledger(&handler, &reserves_id, deposit_id, 100_000, 0);
        // No invoices added

        let max = handler.get_max_outstanding_invoice_amount(partner);
        assert!(max.is_some());
        assert_eq!(max.unwrap(), 0); // No invoices means max is 0
    }

    #[test]
    fn test_list_deposits_multiple_ledgers() {
        let handler = create_test_handler();
        let reserves_id1 = "reserves-120";
        let reserves_id2 = "reserves-121";
        let deposit1 = create_test_deposit_id(122);
        let deposit2 = create_test_deposit_id(123);

        add_operator_ledger(&handler, reserves_id1);
        add_operator_ledger(&handler, reserves_id2);
        add_deposit_to_ledger(&handler, reserves_id1, deposit1, 100_000, 0);
        add_deposit_to_ledger(&handler, reserves_id2, deposit2, 200_000, 0);

        let deposits = handler.list_deposits().unwrap();
        assert_eq!(deposits.len(), 2);
        assert!(deposits.contains(&deposit1));
        assert!(deposits.contains(&deposit2));
    }
}
