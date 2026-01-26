// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Testing helpers for the Bitcoin Deposits protocol.
//!
//! This module contains constructors and utilities for creating DepositsHandler
//! instances in test environments.

use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;

use super::core::DepositsHandler;
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync + 'static> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// This cracks open the private API dependencies to enable full application-level testing.
    /// Creates a handler with a test EventQueue and store.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_testing(logger: L) -> Self
    where
        L::Target: LdkLogger,
        L: Clone + Send + Sync + 'static,
    {
        use crate::event::EventQueue;
        use crate::types::DynStore;
        use lightning::util::persist::KVStoreSync;
        use lightning::io;
        use std::sync::RwLock;
        use std::collections::HashMap;

        // Create a simple in-memory store for testing
        #[derive(Debug)]
        struct TestMemoryStore(RwLock<HashMap<String, Vec<u8>>>);

        impl KVStoreSync for TestMemoryStore {
            fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Result<Vec<u8>, lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.read().unwrap().get(&full_key).cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))
            }

            fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>) -> Result<(), lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.write().unwrap().insert(full_key, buf);
                Ok(())
            }

            fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool) -> Result<(), lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.write().unwrap().remove(&full_key);
                Ok(())
            }

            fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
                let prefix = format!("{}:{}:", primary_namespace, secondary_namespace);
                let keys: Vec<String> = self.0.read().unwrap()
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .map(|k| k[prefix.len()..].to_string())
                    .collect();
                Ok(keys)
            }
        }

        let kv_store: Arc<DynStore> = Arc::new(TestMemoryStore(RwLock::new(HashMap::new())));
        let event_queue = Arc::new(EventQueue::new(logger.clone()));

        // Generate a test node ID
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let test_node_id = PublicKey::from_secret_key(&secp, &secret);

        let mut handler = Self::new(event_queue, logger, kv_store, test_node_id, bitcoin::Network::Regtest).expect("Test handler creation should not fail");
        handler.initialize_core_handler();
        handler
    }

    /// Create a test handler with a specific node ID for replay testing
    ///
    /// This allows replaying captured peer messages where the node ID must match
    /// the original node that received the messages.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_testing_with_node_id(logger: L, node_id: PublicKey) -> Self
    where
        L::Target: LdkLogger,
        L: Clone + Send + Sync + 'static,
    {
        use crate::event::EventQueue;
        use crate::types::DynStore;
        use lightning::util::persist::KVStoreSync;
        use lightning::io;
        use std::sync::RwLock;
        use std::collections::HashMap;

        // Create a simple in-memory store for testing
        #[derive(Debug)]
        struct TestMemoryStore(RwLock<HashMap<String, Vec<u8>>>);

        impl KVStoreSync for TestMemoryStore {
            fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Result<Vec<u8>, lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.read().unwrap().get(&full_key).cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))
            }

            fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>) -> Result<(), lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.write().unwrap().insert(full_key, buf);
                Ok(())
            }

            fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool) -> Result<(), lightning::io::Error> {
                let full_key = format!("{}:{}:{}", primary_namespace, secondary_namespace, key);
                self.0.write().unwrap().remove(&full_key);
                Ok(())
            }

            fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
                let prefix = format!("{}:{}:", primary_namespace, secondary_namespace);
                let keys: Vec<String> = self.0.read().unwrap()
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .map(|k| k[prefix.len()..].to_string())
                    .collect();
                Ok(keys)
            }
        }

        let kv_store: Arc<DynStore> = Arc::new(TestMemoryStore(RwLock::new(HashMap::new())));
        let event_queue = Arc::new(EventQueue::new(logger.clone()));

        let mut handler = Self::new(event_queue, logger, kv_store, node_id, bitcoin::Network::Regtest).expect("Test handler creation should not fail");
        handler.initialize_core_handler();
        handler
    }

    /// Drop all ledgers and related state (NON-CONFORMING - for testing only)
    /// This clears ledgers, signed_update_logs, and persisted data
    #[cfg(feature = "bitcoin-deposits-non-conforming")]
    pub fn drop_all_ledgers(&self) -> usize {
        use lightning::util::persist::KVStoreSync;
        use deposits_core::log_warn;
        use lightning::util::logger::Logger as LdkLogger;

        let mut ledgers = self.ledgers.lock().unwrap();
        let mut signed_update_logs = self.signed_update_logs.lock().unwrap();

        let count = ledgers.len();

        // Clear in-memory state
        ledgers.clear();
        signed_update_logs.clear();

        // Clear broadcast and ACK tracking state - critical for clean reinit
        self.sent_messages_for_broadcast.lock().unwrap().clear();
        self.pending_acks.lock().unwrap().clear();
        self.pending_consent_requests.lock().unwrap().clear();
        self.pending_oneshot_acks.lock().unwrap().clear();
        self.broadcast_sequence_numbers.lock().unwrap().clear();

        // Clear persisted ledger data
        if let Ok(keys) = self.kv_store.list("deposits", "ledgers") {
            for key in keys {
                if let Err(e) = self.kv_store.remove("deposits", "ledgers", &key, false) {
                    log_warn!(self.logger, "Failed to remove persisted ledger {}: {:?}", key, e);
                }
            }
        }

        // Clear persisted audit ledger data
        if let Ok(keys) = self.kv_store.list("deposits", "audit_ledgers") {
            for key in keys {
                if let Err(e) = self.kv_store.remove("deposits", "audit_ledgers", &key, false) {
                    log_warn!(self.logger, "Failed to remove persisted audit ledger {}: {:?}", key, e);
                }
            }
        }

        // Clear persisted signed update logs
        if let Ok(keys) = self.kv_store.list("deposits", "signed_update_logs") {
            for key in keys {
                if let Err(e) = self.kv_store.remove("deposits", "signed_update_logs", &key, false) {
                    log_warn!(self.logger, "Failed to remove persisted signed update log {}: {:?}", key, e);
                }
            }
        }

        log_warn!(
            self.logger,
            "⚠️ NON-CONFORMING: Dropped {} ledgers and all audit state (including persisted data)",
            count
        );

        count
    }
}
