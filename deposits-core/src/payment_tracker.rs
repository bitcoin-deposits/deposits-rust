// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Deposit Invoice Payment Tracking
//!
//! This module provides a standalone `DepositInvoiceIndex` that maintains an O(1) index
//! for payment-to-deposit lookups, enabling quick validation of incoming payments
//! before they are credited.
//!
//! The index is independent of any Lightning implementation and can be used
//! directly or wrapped by handler implementations that need additional functionality
//! like logging.

use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::handler_traits::PaymentTracking;

/// Index mapping payment hashes to deposit invoice info for O(1) lookup.
///
/// This is an index, not the source of truth - deposit.invoices in the ledger is the SOT.
/// Populated when invoice is cosigned, cleaned up when payment is credited.
///
/// CRITICAL: Must check this BEFORE calling claim_funds() to prevent uncredited payments.
#[derive(Default)]
pub struct DepositInvoiceIndex {
    /// Maps payment_hash -> (reserves_id, deposit_pubkey, invoice_id, bolt11)
    payments: Mutex<HashMap<[u8; 32], (PublicKey, PublicKey, String, String)>>,
}

impl DepositInvoiceIndex {
    /// Create a new empty index
    pub fn new() -> Self {
        Self {
            payments: Mutex::new(HashMap::new()),
        }
    }

    /// Get the number of tracked payments
    pub fn len(&self) -> usize {
        self.payments.lock().unwrap().len()
    }

    /// Check if there are no tracked payments
    pub fn is_empty(&self) -> bool {
        self.payments.lock().unwrap().is_empty()
    }
}

impl PaymentTracking for DepositInvoiceIndex {
    fn is_deposit_invoice_payment(&self, payment_hash: &[u8; 32]) -> bool {
        let payments = self.payments.lock().unwrap();
        payments.contains_key(payment_hash)
    }

    fn register_deposit_invoice(
        &self,
        payment_hash: [u8; 32],
        reserves_id: PublicKey,
        deposit_pubkey: PublicKey,
        invoice_id: String,
        bolt11: String,
    ) {
        let mut payments = self.payments.lock().unwrap();
        payments.insert(payment_hash, (reserves_id, deposit_pubkey, invoice_id, bolt11));
    }

    fn get_deposit_invoice_bolt11(&self, payment_hash: &[u8; 32]) -> Option<String> {
        let payments = self.payments.lock().unwrap();
        payments.get(payment_hash).map(|(_, _, _, bolt11)| bolt11.clone())
    }

    fn get_deposit_for_payment(&self, payment_hash: &[u8; 32]) -> Option<(PublicKey, PublicKey, String, String)> {
        let payments = self.payments.lock().unwrap();
        payments.get(payment_hash).cloned()
    }

    fn unregister_deposit_invoice(&self, payment_hash: &[u8; 32]) {
        let mut payments = self.payments.lock().unwrap();
        payments.remove(payment_hash);
    }

    fn cleanup_payments_for_partner(&self, partner_node_id: PublicKey) {
        let mut payments = self.payments.lock().unwrap();
        payments.retain(|_, (partner, _, _, _)| *partner != partner_node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_register_and_check_payment() {
        let tracker = DepositInvoiceIndex::new();
        let payment_hash = [0xAB; 32];
        let partner = create_test_pubkey(1);
        let deposit = create_test_pubkey(2);

        assert!(!tracker.is_deposit_invoice_payment(&payment_hash));
        assert!(tracker.is_empty());

        tracker.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-123".to_string(),
            "lnbc1test".to_string(),
        );

        assert!(tracker.is_deposit_invoice_payment(&payment_hash));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_get_deposit_for_payment() {
        let tracker = DepositInvoiceIndex::new();
        let payment_hash = [0xCD; 32];
        let partner = create_test_pubkey(3);
        let deposit = create_test_pubkey(4);

        assert!(tracker.get_deposit_for_payment(&payment_hash).is_none());

        tracker.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-456".to_string(),
            "lnbc2test".to_string(),
        );

        let result = tracker.get_deposit_for_payment(&payment_hash);
        assert!(result.is_some());
        let (p, d, id, bolt11) = result.unwrap();
        assert_eq!(p, partner);
        assert_eq!(d, deposit);
        assert_eq!(id, "inv-456");
        assert_eq!(bolt11, "lnbc2test");
    }

    #[test]
    fn test_get_bolt11() {
        let tracker = DepositInvoiceIndex::new();
        let payment_hash = [0xEF; 32];
        let partner = create_test_pubkey(5);
        let deposit = create_test_pubkey(6);

        tracker.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-789".to_string(),
            "lnbc3mytestinvoice".to_string(),
        );

        assert_eq!(
            tracker.get_deposit_invoice_bolt11(&payment_hash),
            Some("lnbc3mytestinvoice".to_string())
        );
    }

    #[test]
    fn test_unregister_payment() {
        let tracker = DepositInvoiceIndex::new();
        let payment_hash = [0x12; 32];
        let partner = create_test_pubkey(7);
        let deposit = create_test_pubkey(8);

        tracker.register_deposit_invoice(
            payment_hash,
            partner,
            deposit,
            "inv-abc".to_string(),
            "lnbc4test".to_string(),
        );
        assert!(tracker.is_deposit_invoice_payment(&payment_hash));

        tracker.unregister_deposit_invoice(&payment_hash);
        assert!(!tracker.is_deposit_invoice_payment(&payment_hash));
    }

    #[test]
    fn test_cleanup_payments_for_partner() {
        let tracker = DepositInvoiceIndex::new();
        let partner1 = create_test_pubkey(10);
        let partner2 = create_test_pubkey(11);
        let deposit1 = create_test_pubkey(12);
        let deposit2 = create_test_pubkey(13);

        let hash1 = [0x21; 32];
        let hash2 = [0x22; 32];
        let hash3 = [0x23; 32];

        tracker.register_deposit_invoice(hash1, partner1, deposit1, "inv1".to_string(), "bolt1".to_string());
        tracker.register_deposit_invoice(hash2, partner1, deposit1, "inv2".to_string(), "bolt2".to_string());
        tracker.register_deposit_invoice(hash3, partner2, deposit2, "inv3".to_string(), "bolt3".to_string());

        assert_eq!(tracker.len(), 3);

        tracker.cleanup_payments_for_partner(partner1);

        assert!(!tracker.is_deposit_invoice_payment(&hash1));
        assert!(!tracker.is_deposit_invoice_payment(&hash2));
        assert!(tracker.is_deposit_invoice_payment(&hash3));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let tracker = DepositInvoiceIndex::new();
        let payment_hash = [0x99; 32];

        // Should not panic
        tracker.unregister_deposit_invoice(&payment_hash);
        assert!(!tracker.is_deposit_invoice_payment(&payment_hash));
    }
}
