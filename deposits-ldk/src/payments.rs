// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Payment Tracker Implementation
//!
//! Implements the `PaymentTracker` trait for tracking Lightning payments
//! needed by the Bitcoin Deposits protocol.

use deposits_core::traits::{PaymentTracker, PaymentStatus};

use std::collections::HashMap;
use std::sync::Mutex;

/// Payment record for tracking status and preimages.
#[derive(Clone, Debug)]
pub struct PaymentRecord {
    /// Payment status
    pub status: PaymentStatus,
    /// Amount in millisatoshis (if known)
    pub amount_msat: Option<u64>,
    /// Preimage (if payment succeeded)
    pub preimage: Option<[u8; 32]>,
}

/// LDK-based payment tracker.
///
/// This adapter wraps a callback that queries LDK's payment state.
/// The callback is provided by the host application which has access
/// to the full payment tracking infrastructure.
pub struct LdkPaymentTracker {
    /// Callback to check if a payment was received
    check_received: Box<dyn Fn([u8; 32], u64) -> bool + Send + Sync>,
    /// Callback to get payment status
    get_status: Box<dyn Fn([u8; 32]) -> PaymentStatus + Send + Sync>,
    /// Callback to get preimage
    get_preimage: Box<dyn Fn([u8; 32]) -> Option<[u8; 32]> + Send + Sync>,
}

impl LdkPaymentTracker {
    /// Create a new payment tracker with callbacks.
    pub fn new<R, S, P>(
        check_received: R,
        get_status: S,
        get_preimage: P,
    ) -> Self
    where
        R: Fn([u8; 32], u64) -> bool + Send + Sync + 'static,
        S: Fn([u8; 32]) -> PaymentStatus + Send + Sync + 'static,
        P: Fn([u8; 32]) -> Option<[u8; 32]> + Send + Sync + 'static,
    {
        Self {
            check_received: Box::new(check_received),
            get_status: Box::new(get_status),
            get_preimage: Box::new(get_preimage),
        }
    }
}

impl PaymentTracker for LdkPaymentTracker {
    fn payment_received(&self, payment_hash: [u8; 32], amount_msat: u64) -> bool {
        (self.check_received)(payment_hash, amount_msat)
    }

    fn payment_sent(&self, _payment_id: [u8; 32], _success: bool) {
        // No-op for callback-based tracker - LDK handles this
    }

    fn get_payment_status(&self, payment_id: [u8; 32]) -> PaymentStatus {
        (self.get_status)(payment_id)
    }

    fn get_preimage(&self, payment_hash: [u8; 32]) -> Option<[u8; 32]> {
        (self.get_preimage)(payment_hash)
    }
}

/// In-memory payment tracker for testing.
#[derive(Default)]
pub struct MemoryPaymentTracker {
    /// Payments indexed by hash/id
    payments: Mutex<HashMap<[u8; 32], PaymentRecord>>,
}

impl MemoryPaymentTracker {
    /// Create a new in-memory payment tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a received payment.
    pub fn record_received(&self, payment_hash: [u8; 32], amount_msat: u64, preimage: [u8; 32]) {
        let mut payments = self.payments.lock().unwrap();
        payments.insert(payment_hash, PaymentRecord {
            status: PaymentStatus::Succeeded,
            amount_msat: Some(amount_msat),
            preimage: Some(preimage),
        });
    }

    /// Record a pending outgoing payment.
    pub fn record_pending(&self, payment_id: [u8; 32], amount_msat: u64) {
        let mut payments = self.payments.lock().unwrap();
        payments.insert(payment_id, PaymentRecord {
            status: PaymentStatus::Pending,
            amount_msat: Some(amount_msat),
            preimage: None,
        });
    }

    /// Mark a payment as succeeded with preimage.
    pub fn mark_succeeded(&self, payment_id: [u8; 32], preimage: [u8; 32]) {
        let mut payments = self.payments.lock().unwrap();
        if let Some(record) = payments.get_mut(&payment_id) {
            record.status = PaymentStatus::Succeeded;
            record.preimage = Some(preimage);
        }
    }

    /// Mark a payment as failed.
    pub fn mark_failed(&self, payment_id: [u8; 32]) {
        let mut payments = self.payments.lock().unwrap();
        if let Some(record) = payments.get_mut(&payment_id) {
            record.status = PaymentStatus::Failed;
        }
    }

    /// Get a payment record.
    pub fn get_record(&self, payment_id: [u8; 32]) -> Option<PaymentRecord> {
        let payments = self.payments.lock().unwrap();
        payments.get(&payment_id).cloned()
    }
}

impl PaymentTracker for MemoryPaymentTracker {
    fn payment_received(&self, payment_hash: [u8; 32], amount_msat: u64) -> bool {
        let payments = self.payments.lock().unwrap();
        if let Some(record) = payments.get(&payment_hash) {
            record.status == PaymentStatus::Succeeded
                && record.amount_msat.map(|a| a >= amount_msat).unwrap_or(false)
        } else {
            false
        }
    }

    fn payment_sent(&self, payment_id: [u8; 32], success: bool) {
        let mut payments = self.payments.lock().unwrap();
        if let Some(record) = payments.get_mut(&payment_id) {
            record.status = if success {
                PaymentStatus::Succeeded
            } else {
                PaymentStatus::Failed
            };
        }
    }

    fn get_payment_status(&self, payment_id: [u8; 32]) -> PaymentStatus {
        let payments = self.payments.lock().unwrap();
        payments
            .get(&payment_id)
            .map(|r| r.status)
            .unwrap_or(PaymentStatus::Unknown)
    }

    fn get_preimage(&self, payment_hash: [u8; 32]) -> Option<[u8; 32]> {
        let payments = self.payments.lock().unwrap();
        payments.get(&payment_hash).and_then(|r| r.preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_tracker_received() {
        let tracker = MemoryPaymentTracker::new();
        let hash = [1u8; 32];
        let preimage = [2u8; 32];

        // Not received yet
        assert!(!tracker.payment_received(hash, 1000));
        assert_eq!(tracker.get_payment_status(hash), PaymentStatus::Unknown);

        // Record received
        tracker.record_received(hash, 1000, preimage);

        // Now received
        assert!(tracker.payment_received(hash, 1000));
        assert!(tracker.payment_received(hash, 500)); // Less than received is ok
        assert!(!tracker.payment_received(hash, 2000)); // More than received is not
        assert_eq!(tracker.get_payment_status(hash), PaymentStatus::Succeeded);
        assert_eq!(tracker.get_preimage(hash), Some(preimage));
    }

    #[test]
    fn test_memory_tracker_outgoing() {
        let tracker = MemoryPaymentTracker::new();
        let id = [1u8; 32];
        let preimage = [2u8; 32];

        // Record pending
        tracker.record_pending(id, 1000);
        assert_eq!(tracker.get_payment_status(id), PaymentStatus::Pending);
        assert_eq!(tracker.get_preimage(id), None);

        // Mark succeeded
        tracker.mark_succeeded(id, preimage);
        assert_eq!(tracker.get_payment_status(id), PaymentStatus::Succeeded);
        assert_eq!(tracker.get_preimage(id), Some(preimage));
    }

    #[test]
    fn test_memory_tracker_failed() {
        let tracker = MemoryPaymentTracker::new();
        let id = [1u8; 32];

        tracker.record_pending(id, 1000);
        tracker.mark_failed(id);

        assert_eq!(tracker.get_payment_status(id), PaymentStatus::Failed);
    }

    #[test]
    fn test_callback_tracker() {
        let tracker = LdkPaymentTracker::new(
            |hash, _amount| hash[0] == 42, // Only "receive" if first byte is 42
            |id| {
                if id[0] == 1 { PaymentStatus::Pending }
                else if id[0] == 2 { PaymentStatus::Succeeded }
                else { PaymentStatus::Unknown }
            },
            |hash| {
                if hash[0] == 2 { Some([99u8; 32]) }
                else { None }
            },
        );

        // Test received
        assert!(tracker.payment_received([42u8; 32], 1000));
        assert!(!tracker.payment_received([1u8; 32], 1000));

        // Test status
        assert_eq!(tracker.get_payment_status([1u8; 32]), PaymentStatus::Pending);
        assert_eq!(tracker.get_payment_status([2u8; 32]), PaymentStatus::Succeeded);
        assert_eq!(tracker.get_payment_status([3u8; 32]), PaymentStatus::Unknown);

        // Test preimage
        assert_eq!(tracker.get_preimage([2u8; 32]), Some([99u8; 32]));
        assert_eq!(tracker.get_preimage([1u8; 32]), None);
    }
}
