// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Storage Implementation
//!
//! Implements the `Storage` trait using LDK's KVStore interface.

use deposits_core::traits::{Storage, StorageError};
use lightning::util::persist::KVStoreSync;

use std::sync::Arc;

/// Storage namespace for Bitcoin Deposits data.
pub const DEPOSITS_NAMESPACE: &str = "deposits";

/// LDK-based storage adapter for Bitcoin Deposits protocol.
///
/// Wraps an LDK KVStoreSync to provide the Storage trait interface
/// needed by deposits-core.
pub struct LdkStorage<K: KVStoreSync + ?Sized> {
    /// The underlying KVStore
    kv_store: Arc<K>,
    /// Primary namespace for all deposits data
    namespace: String,
}

impl<K: KVStoreSync + ?Sized> LdkStorage<K> {
    /// Create a new LDK storage adapter.
    pub fn new(kv_store: Arc<K>) -> Self {
        Self {
            kv_store,
            namespace: DEPOSITS_NAMESPACE.to_string(),
        }
    }

    /// Create with a custom namespace.
    pub fn with_namespace(kv_store: Arc<K>, namespace: String) -> Self {
        Self { kv_store, namespace }
    }

    /// Convert a key to (secondary_namespace, key_name) for KVStore.
    fn split_key(&self, key: &[u8]) -> (String, String) {
        // Use hex encoding for the key to ensure it's a valid string
        let key_hex = hex::encode(key);

        // Split key into secondary namespace and key name
        // Format: first 2 bytes as secondary namespace, rest as key
        if key.len() > 2 {
            let secondary = hex::encode(&key[..2]);
            let key_name = hex::encode(&key[2..]);
            (secondary, key_name)
        } else {
            ("default".to_string(), key_hex)
        }
    }
}

impl<K: KVStoreSync + Send + Sync + ?Sized> Storage for LdkStorage<K> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let (secondary, key_name) = self.split_key(key);

        match self.kv_store.read(&self.namespace, &secondary, &key_name) {
            Ok(data) => Ok(Some(data)),
            Err(e) => {
                // Check if it's a "not found" error
                let err_str = format!("{:?}", e);
                if err_str.contains("NotFound") || err_str.contains("No such file") {
                    Ok(None)
                } else {
                    Err(StorageError::IoError(err_str))
                }
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let (secondary, key_name) = self.split_key(key);

        self.kv_store
            .write(&self.namespace, &secondary, &key_name, value.to_vec())
            .map_err(|e| StorageError::IoError(format!("{:?}", e)))
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let (secondary, key_name) = self.split_key(key);

        match self.kv_store.remove(&self.namespace, &secondary, &key_name, false) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Ignore "not found" errors on delete
                let err_str = format!("{:?}", e);
                if err_str.contains("NotFound") || err_str.contains("No such file") {
                    Ok(())
                } else {
                    Err(StorageError::IoError(err_str))
                }
            }
        }
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        // KVStore doesn't have a native scan_prefix, so we need to list keys
        // and filter manually. For now, return empty - this would need
        // implementation-specific handling.
        //
        // In practice, the caller should use a more sophisticated storage
        // backend that supports prefix scanning, or maintain an index.

        let (secondary, _) = self.split_key(prefix);

        match self.kv_store.list(&self.namespace, &secondary) {
            Ok(keys) => {
                let mut results = Vec::new();
                let prefix_hex = hex::encode(prefix);

                for key_name in keys {
                    // Check if key starts with prefix
                    if key_name.starts_with(&prefix_hex[4..]) {
                        // 4 = len of secondary namespace hex
                        // Reconstruct full key
                        if let Ok(key_bytes) = hex::decode(format!("{}{}", &prefix_hex[..4], &key_name))
                        {
                            // Read the value
                            if let Ok(value) =
                                self.kv_store.read(&self.namespace, &secondary, &key_name)
                            {
                                results.push((key_bytes, value));
                            }
                        }
                    }
                }

                // Sort by key
                results.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(results)
            }
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("NotFound") || err_str.contains("No such file") {
                    Ok(Vec::new())
                } else {
                    Err(StorageError::IoError(err_str))
                }
            }
        }
    }
}

/// In-memory storage for testing.
#[derive(Default)]
pub struct MemoryStorage {
    data: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryStorage {
    /// Create a new in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let data = self.data.lock().unwrap();
        Ok(data.get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut data = self.data.lock().unwrap();
        data.remove(key);
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let data = self.data.lock().unwrap();
        let results: Vec<_> = data
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_basic() {
        let storage = MemoryStorage::new();

        // Put and get
        storage.put(b"key1", b"value1").unwrap();
        assert_eq!(storage.get(b"key1").unwrap(), Some(b"value1".to_vec()));

        // Get nonexistent
        assert_eq!(storage.get(b"nonexistent").unwrap(), None);

        // Delete
        storage.delete(b"key1").unwrap();
        assert_eq!(storage.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_memory_storage_scan_prefix() {
        let storage = MemoryStorage::new();

        storage.put(b"prefix:1", b"v1").unwrap();
        storage.put(b"prefix:2", b"v2").unwrap();
        storage.put(b"prefix:3", b"v3").unwrap();
        storage.put(b"other:1", b"o1").unwrap();

        let results = storage.scan_prefix(b"prefix:").unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, b"prefix:1".to_vec());
        assert_eq!(results[1].0, b"prefix:2".to_vec());
        assert_eq!(results[2].0, b"prefix:3".to_vec());
    }

    #[test]
    fn test_memory_storage_exists() {
        let storage = MemoryStorage::new();

        assert!(!storage.exists(b"key").unwrap());
        storage.put(b"key", b"value").unwrap();
        assert!(storage.exists(b"key").unwrap());
    }
}
