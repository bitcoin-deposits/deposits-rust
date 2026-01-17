//! Payment Tracking for Bitcoin Deposits
//!
//! This module handles registration and lookup of deposit invoice payments.
//! It maintains an O(1) index for payment-to-deposit lookups, enabling quick
//! validation of incoming payments before they are credited.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use lightning::log_info;
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

// Re-export trait from deposits-core for backwards compatibility
pub use deposits_core::handler_traits::PaymentTracking;

impl<L: Deref + Clone> PaymentTracking for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn is_deposit_invoice_payment(&self, payment_hash: &[u8; 32]) -> bool {
        let payment_deposits = self.payment_deposits.lock().unwrap();
        payment_deposits.contains_key(payment_hash)
    }

    fn register_deposit_invoice(
        &self,
        payment_hash: [u8; 32],
        partner_id: PublicKey,
        deposit_pubkey: PublicKey,
        invoice_id: String,
        bolt11: String,
    ) {
        let mut payment_deposits = self.payment_deposits.lock().unwrap();
        payment_deposits.insert(payment_hash, (partner_id, deposit_pubkey, invoice_id.clone(), bolt11));
        log_info!(
            self.logger,
            "₿ Registered payment hash {} for deposit {} (invoice: {})",
            crate::hex_utils::to_string(&payment_hash),
            deposit_pubkey,
            invoice_id
        );
    }

    fn get_deposit_invoice_bolt11(&self, payment_hash: &[u8; 32]) -> Option<String> {
        let payment_deposits = self.payment_deposits.lock().unwrap();
        payment_deposits.get(payment_hash).map(|(_, _, _, bolt11)| bolt11.clone())
    }

    fn get_deposit_for_payment(&self, payment_hash: &[u8; 32]) -> Option<(PublicKey, PublicKey, String, String)> {
        let payment_deposits = self.payment_deposits.lock().unwrap();
        payment_deposits.get(payment_hash).cloned()
    }

    fn unregister_deposit_invoice(&self, payment_hash: &[u8; 32]) {
        let mut payment_deposits = self.payment_deposits.lock().unwrap();
        if payment_deposits.remove(payment_hash).is_some() {
            log_info!(
                self.logger,
                "₿ Unregistered payment hash {}",
                crate::hex_utils::to_string(payment_hash)
            );
        }
    }

    fn cleanup_payments_for_partner(&self, partner_node_id: PublicKey) {
        let mut payment_deposits = self.payment_deposits.lock().unwrap();
        payment_deposits.retain(|_, (partner, _, _, _)| *partner != partner_node_id);
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
    fn test_register_and_check_payment() {
        let handler = create_test_handler();
        let payment_hash = [0xAB; 32];
        let partner = create_test_pubkey(1);
        let deposit = create_test_pubkey(2);

        assert!(!handler.is_deposit_invoice_payment(&payment_hash));

        handler.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-123".to_string(),
            "lnbc1test".to_string(),
        );

        assert!(handler.is_deposit_invoice_payment(&payment_hash));
    }

    #[test]
    fn test_get_deposit_for_payment() {
        let handler = create_test_handler();
        let payment_hash = [0xCD; 32];
        let partner = create_test_pubkey(3);
        let deposit = create_test_pubkey(4);

        assert!(handler.get_deposit_for_payment(&payment_hash).is_none());

        handler.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-456".to_string(),
            "lnbc2test".to_string(),
        );

        let result = handler.get_deposit_for_payment(&payment_hash);
        assert!(result.is_some());
        let (p, d, id, bolt11) = result.unwrap();
        assert_eq!(p, partner);
        assert_eq!(d, deposit);
        assert_eq!(id, "inv-456");
        assert_eq!(bolt11, "lnbc2test");
    }

    #[test]
    fn test_get_bolt11() {
        let handler = create_test_handler();
        let payment_hash = [0xEF; 32];
        let partner = create_test_pubkey(5);
        let deposit = create_test_pubkey(6);

        handler.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-789".to_string(),
            "lnbc3mytestinvoice".to_string(),
        );

        assert_eq!(
            handler.get_deposit_invoice_bolt11(&payment_hash),
            Some("lnbc3mytestinvoice".to_string())
        );
    }

    #[test]
    fn test_unregister_payment() {
        let handler = create_test_handler();
        let payment_hash = [0x12; 32];
        let partner = create_test_pubkey(7);
        let deposit = create_test_pubkey(8);

        handler.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-abc".to_string(),
            "lnbc4test".to_string(),
        );
        assert!(handler.is_deposit_invoice_payment(&payment_hash));

        handler.unregister_deposit_invoice(&payment_hash);
        assert!(!handler.is_deposit_invoice_payment(&payment_hash));
    }

    #[test]
    fn test_cleanup_payments_for_partner() {
        let handler = create_test_handler();
        let partner1 = create_test_pubkey(10);
        let partner2 = create_test_pubkey(11);
        let deposit1 = create_test_pubkey(12);
        let deposit2 = create_test_pubkey(13);

        let hash1 = [0x21; 32];
        let hash2 = [0x22; 32];
        let hash3 = [0x23; 32];

        handler.register_deposit_invoice(hash1, partner1, deposit1, "inv1".to_string(), "bolt1".to_string());
        handler.register_deposit_invoice(hash2, partner1, deposit1, "inv2".to_string(), "bolt2".to_string());
        handler.register_deposit_invoice(hash3, partner2, deposit2, "inv3".to_string(), "bolt3".to_string());

        handler.cleanup_payments_for_partner(partner1);

        assert!(!handler.is_deposit_invoice_payment(&hash1));
        assert!(!handler.is_deposit_invoice_payment(&hash2));
        assert!(handler.is_deposit_invoice_payment(&hash3));
    }

    #[test]
    fn test_unregister_nonexistent() {
        let handler = create_test_handler();
        let payment_hash = [0x99; 32];

        // Should not panic
        handler.unregister_deposit_invoice(&payment_hash);
        assert!(!handler.is_deposit_invoice_payment(&payment_hash));
    }
}
