// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Serde helpers and deposit identifier utilities.

use bitcoin::hashes::{sha256, Hash};

// ============================================================================
// Serde Helpers
// ============================================================================

/// Serde helper for PublicKey
pub mod serde_pubkey {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a PublicKey
    pub fn serialize<S>(pubkey: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        pubkey.serialize().as_slice().serialize(serializer)
    }

    /// Deserialize a PublicKey
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        PublicKey::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for 32-byte arrays
pub mod serde_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a 32-byte array
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    /// Deserialize a 32-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected 32 bytes, got {}",
                vec.len()
            )))
        }
    }
}

/// Serde helper for 64-byte arrays
pub mod serde_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a 64-byte array
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    /// Deserialize a 64-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                vec.len()
            )))
        }
    }
}

/// Serde helper for Option<[u8; 64]>
pub mod serde_opt_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize an optional 64-byte array
    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => bytes.as_slice().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an optional 64-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) if vec.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&vec);
                Ok(Some(arr))
            }
            Some(vec) => Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                vec.len()
            ))),
            None => Ok(None),
        }
    }
}

/// Serde helper for HashMap<PublicKey, V> - serializes as Vec of tuples
pub mod serde_pubkey_map {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_pubkey")]
        key: PublicKey,
        value: V,
    }

    /// Serialize a HashMap<PublicKey, V>
    pub fn serialize<S, V>(map: &HashMap<PublicKey, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<PublicKey, V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<PublicKey, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}

/// Serde helper for Vec<PublicKey>
pub mod serde_pubkey_vec {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a Vec<PublicKey>
    pub fn serialize<S>(vec: &[PublicKey], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = vec.iter().map(|pk| pk.serialize().to_vec()).collect();
        bytes.serialize(serializer)
    }

    /// Deserialize a Vec<PublicKey>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        bytes
            .into_iter()
            .map(|b| PublicKey::from_slice(&b).map_err(serde::de::Error::custom))
            .collect()
    }
}

// ============================================================================
// Deposit Identifier
// ============================================================================

/// Unique deposit identifier derived from descriptor.
/// This is the first 16 bytes of SHA256(descriptor_string).
pub type DepositId = [u8; 16];

/// Compute a DepositId from a descriptor string.
/// deposit_id = SHA256(descriptor_string)[0..16]
pub fn compute_deposit_id(descriptor: &str) -> DepositId {
    let hash = sha256::Hash::hash(descriptor.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[0..16]);
    id
}

/// Serde helper for DepositId (16-byte array)
pub mod serde_deposit_id {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a DepositId as hex string
    pub fn serialize<S>(id: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(id).serialize(serializer)
    }

    /// Deserialize a DepositId from hex string
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "Expected 16 bytes for DepositId, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serde helper for HashMap<DepositId, V> - serializes as Vec of tuples with hex keys
pub mod serde_deposit_id_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_deposit_id")]
        key: [u8; 16],
        value: V,
    }

    /// Serialize a HashMap<DepositId, V>
    pub fn serialize<S, V>(map: &HashMap<[u8; 16], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<DepositId, V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<[u8; 16], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}

/// Serde helper for HashMap<[u8; 32], V> (transfer_id maps)
pub mod serde_transfer_id_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_32")]
        key: [u8; 32],
        value: V,
    }

    /// Serialize a HashMap<[u8; 32], V>
    pub fn serialize<S, V>(map: &HashMap<[u8; 32], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<[u8; 32], V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<[u8; 32], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}
