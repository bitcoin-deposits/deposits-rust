// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Chain Source Implementation
//!
//! Implements the `ChainSource` and `Broadcaster` traits using LDK interfaces.

use bitcoin::Transaction;
use deposits_core::traits::{Broadcaster, BroadcastError, ChainSource};
use lightning::chain::chaininterface::BroadcasterInterface;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// LDK-based chain source for Bitcoin Deposits protocol.
///
/// Provides block height and hash queries.
pub struct LdkChainSource {
    /// Current best block height
    current_height: AtomicU32,
    /// Block hashes by height (sparse)
    block_hashes: Mutex<std::collections::HashMap<u32, [u8; 32]>>,
}

impl LdkChainSource {
    /// Create a new chain source with initial height.
    pub fn new(initial_height: u32) -> Self {
        Self {
            current_height: AtomicU32::new(initial_height),
            block_hashes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Update the current block height.
    pub fn set_height(&self, height: u32) {
        self.current_height.store(height, Ordering::SeqCst);
    }

    /// Record a block hash at a specific height.
    pub fn set_block_hash(&self, height: u32, hash: [u8; 32]) {
        let mut hashes = self.block_hashes.lock().unwrap();
        hashes.insert(height, hash);
    }
}

impl Default for LdkChainSource {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ChainSource for LdkChainSource {
    fn current_height(&self) -> u32 {
        self.current_height.load(Ordering::SeqCst)
    }

    fn get_block_hash(&self, height: u32) -> Option<[u8; 32]> {
        let hashes = self.block_hashes.lock().unwrap();
        hashes.get(&height).copied()
    }

    fn fee_rate(&self, _confirmation_target: u32) -> Option<u64> {
        // Default fee rate - in production, this should query the fee estimator
        Some(10) // 10 sat/vbyte default
    }
}

/// LDK-based transaction broadcaster.
pub struct LdkBroadcaster<B: BroadcasterInterface> {
    broadcaster: Arc<B>,
}

impl<B: BroadcasterInterface> LdkBroadcaster<B> {
    /// Create a new broadcaster wrapper.
    pub fn new(broadcaster: Arc<B>) -> Self {
        Self { broadcaster }
    }
}

impl<B: BroadcasterInterface + Send + Sync> Broadcaster for LdkBroadcaster<B> {
    fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), BroadcastError> {
        self.broadcaster.broadcast_transactions(&[tx]);
        Ok(())
    }
}

/// Simple in-memory broadcaster for testing.
#[derive(Default)]
pub struct MemoryBroadcaster {
    /// Broadcasted transactions
    transactions: Mutex<Vec<Transaction>>,
}

impl MemoryBroadcaster {
    /// Create a new in-memory broadcaster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all broadcasted transactions.
    pub fn get_transactions(&self) -> Vec<Transaction> {
        let txs = self.transactions.lock().unwrap();
        txs.clone()
    }

    /// Clear broadcasted transactions.
    pub fn clear(&self) {
        let mut txs = self.transactions.lock().unwrap();
        txs.clear();
    }
}

impl Broadcaster for MemoryBroadcaster {
    fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), BroadcastError> {
        let mut txs = self.transactions.lock().unwrap();
        txs.push(tx.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_source_height() {
        let chain = LdkChainSource::new(100);
        assert_eq!(chain.current_height(), 100);

        chain.set_height(150);
        assert_eq!(chain.current_height(), 150);
    }

    #[test]
    fn test_chain_source_block_hash() {
        let chain = LdkChainSource::new(100);

        // No hash initially
        assert_eq!(chain.get_block_hash(100), None);

        // Set hash
        let hash = [42u8; 32];
        chain.set_block_hash(100, hash);
        assert_eq!(chain.get_block_hash(100), Some(hash));

        // Other heights still return None
        assert_eq!(chain.get_block_hash(99), None);
        assert_eq!(chain.get_block_hash(101), None);
    }

    #[test]
    fn test_chain_source_fee_rate() {
        let chain = LdkChainSource::new(100);
        assert!(chain.fee_rate(6).is_some());
    }

    #[test]
    fn test_memory_broadcaster() {
        let broadcaster = MemoryBroadcaster::new();

        // Create a minimal test transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Broadcast
        broadcaster.broadcast_transaction(&tx).unwrap();

        // Check
        let txs = broadcaster.get_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0], tx);

        // Clear
        broadcaster.clear();
        assert!(broadcaster.get_transactions().is_empty());
    }
}
