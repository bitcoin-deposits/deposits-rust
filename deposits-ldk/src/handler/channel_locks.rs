//! Channel Lock Management for Bitcoin Deposits
//!
//! This module provides per-channel operation locks to prevent commitment
//! signature races when multiple operations happen in parallel on the same
//! Lightning channel.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;
use std::sync::Arc;

use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;
use super::ledger_ops::LedgerOperationsExt;

/// Extension trait for channel lock operations on DepositsHandler
pub trait ChannelLocks {
    /// Execute a function while holding the channel operation lock
    /// This prevents commitment signature races when multiple operations
    /// happen in parallel on the same Lightning channel
    /// The lock is automatically released when the function returns
    fn with_channel_lock<F, R>(&self, operator_id: PublicKey, partner_id: PublicKey, f: F) -> R
    where
        F: FnOnce() -> R;

    /// Async version of with_channel_lock for use in async contexts
    /// Acquires a per-channel lock to prevent commitment signature races
    /// Returns a guard that releases the lock when dropped
    fn acquire_channel_lock_async(
        &self,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) -> impl std::future::Future<Output = tokio::sync::OwnedMutexGuard<()>> + Send;

    /// Acquire channel lock for a deposit (finds the partner and acquires the lock)
    /// Returns None if the deposit is not found in any ledger
    fn acquire_channel_lock_for_deposit(
        &self,
        deposit_pubkey: PublicKey,
    ) -> impl std::future::Future<Output = Option<tokio::sync::OwnedMutexGuard<()>>> + Send;

    /// Get our node's public key
    fn our_node_id(&self) -> PublicKey;
}

impl<L: Deref + Clone + Send + Sync> ChannelLocks for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn with_channel_lock<F, R>(&self, operator_id: PublicKey, partner_id: PublicKey, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let lock = {
            let mut locks = self.channel_operation_locks.lock().unwrap();
            locks.entry((operator_id, partner_id))
                .or_insert_with(|| Arc::new(std::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().unwrap();
        f()
    }

    async fn acquire_channel_lock_async(
        &self,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.channel_operation_locks_async.lock().await;
            locks.entry((operator_id, partner_id))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    async fn acquire_channel_lock_for_deposit(
        &self,
        deposit_pubkey: PublicKey,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let partner_id = self.find_partner_for_deposit(deposit_pubkey)?;
        Some(self.acquire_channel_lock_async(self.our_node_id, partner_id).await)
    }

    fn our_node_id(&self) -> PublicKey {
        self.our_node_id
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
    fn test_with_channel_lock() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(1);
        let partner = create_test_pubkey(2);

        let result = handler.with_channel_lock(operator, partner, || {
            42
        });

        assert_eq!(result, 42);
    }

    #[test]
    fn test_with_channel_lock_reentrant_different_channels() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(1);
        let partner1 = create_test_pubkey(2);
        let partner2 = create_test_pubkey(3);

        // Different channels should have independent locks
        let result = handler.with_channel_lock(operator, partner1, || {
            handler.with_channel_lock(operator, partner2, || {
                100
            })
        });

        assert_eq!(result, 100);
    }

    #[test]
    fn test_our_node_id() {
        let handler = create_test_handler();
        let our_id = handler.our_node_id();

        // Verify it's a valid public key (not all zeros)
        assert_ne!(our_id.serialize(), [0u8; 33]);
    }

    #[tokio::test]
    async fn test_acquire_channel_lock_async() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(10);
        let partner = create_test_pubkey(11);

        let guard = handler.acquire_channel_lock_async(operator, partner).await;

        // Lock is held
        drop(guard);
        // Lock is released
    }

    #[tokio::test]
    async fn test_acquire_channel_lock_for_deposit_not_found() {
        let handler = create_test_handler();
        let unknown_deposit = create_test_pubkey(99);

        let result = handler.acquire_channel_lock_for_deposit(unknown_deposit).await;
        assert!(result.is_none());
    }
}
