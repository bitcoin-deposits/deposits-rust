// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Channel Registry and Operations Implementation
//!
//! Implements the `ChannelRegistry`, `ChannelOperations`, and `ReservesOperations`
//! traits for use with LDK's ChannelManager.
//!
//! Note: The actual LDK integration requires the full ChannelManager type,
//! which is constructed by the host application. This module provides
//! the trait implementation pattern and memory-based implementations for testing.

use bitcoin::secp256k1::PublicKey;
use deposits_core::traits::{
    ChannelRegistry, ChannelOperations, ReservesOperations,
    ChannelInfo as CoreChannelInfo,
};

use std::collections::HashMap;
use std::sync::Mutex;

/// Channel information (local version for callbacks).
/// This is converted to/from CoreChannelInfo as needed.
#[derive(Clone, Debug)]
pub struct ChannelInfo {
    /// Channel ID (32 bytes)
    pub channel_id: [u8; 32],
    /// Counterparty node public key
    pub counterparty: PublicKey,
    /// Whether the channel is usable for payments
    pub is_usable: bool,
    /// Local balance in millisatoshis
    pub balance_msat: u64,
    /// Funding transaction ID (if confirmed)
    pub funding_txid: Option<[u8; 32]>,
    /// Funding output index
    pub funding_vout: Option<u32>,
    /// Channel capacity in satoshis
    pub channel_value_satoshis: u64,
}

impl From<ChannelInfo> for CoreChannelInfo {
    fn from(info: ChannelInfo) -> Self {
        CoreChannelInfo {
            channel_id: info.channel_id,
            counterparty_node_id: info.counterparty,
            funding_txid: info.funding_txid,
            funding_vout: info.funding_vout,
            is_usable: info.is_usable,
            channel_value_satoshis: info.channel_value_satoshis,
            balance_msat: info.balance_msat,
        }
    }
}

impl From<CoreChannelInfo> for ChannelInfo {
    fn from(info: CoreChannelInfo) -> Self {
        ChannelInfo {
            channel_id: info.channel_id,
            counterparty: info.counterparty_node_id,
            funding_txid: info.funding_txid,
            funding_vout: info.funding_vout,
            is_usable: info.is_usable,
            channel_value_satoshis: info.channel_value_satoshis,
            balance_msat: info.balance_msat,
        }
    }
}

/// LDK-based channel registry for Bitcoin Deposits protocol.
///
/// This implementation wraps a callback that queries the ChannelManager.
/// The callback is provided by the host application which has access to
/// the full ChannelManager type.
pub struct LdkChannelRegistry {
    /// Callback to get all channels
    get_channels: Box<dyn Fn() -> Vec<ChannelInfo> + Send + Sync>,
}

impl LdkChannelRegistry {
    /// Create a new channel registry with a callback.
    ///
    /// The callback should return current channel information from the ChannelManager.
    pub fn new<F>(get_channels: F) -> Self
    where
        F: Fn() -> Vec<ChannelInfo> + Send + Sync + 'static,
    {
        Self {
            get_channels: Box::new(get_channels),
        }
    }
}

impl ChannelRegistry for LdkChannelRegistry {
    fn partner_for_channel(&self, channel_id: [u8; 32]) -> Option<PublicKey> {
        let channels = (self.get_channels)();
        channels
            .iter()
            .find(|c| c.channel_id == channel_id)
            .map(|c| c.counterparty)
    }

    fn channels_with_peer(&self, peer: PublicKey) -> Vec<[u8; 32]> {
        let channels = (self.get_channels)();
        channels
            .iter()
            .filter(|c| c.counterparty == peer)
            .map(|c| c.channel_id)
            .collect()
    }

    fn channel_is_usable(&self, channel_id: [u8; 32]) -> bool {
        let channels = (self.get_channels)();
        channels
            .iter()
            .any(|c| c.channel_id == channel_id && c.is_usable)
    }

    fn channel_balance_msat(&self, channel_id: [u8; 32]) -> Option<u64> {
        let channels = (self.get_channels)();
        channels
            .iter()
            .find(|c| c.channel_id == channel_id)
            .map(|c| c.balance_msat)
    }
}

/// Simple in-memory channel registry for testing.
#[derive(Default)]
pub struct MemoryChannelRegistry {
    /// Map of channel_id -> channel info
    channels: Mutex<HashMap<[u8; 32], ChannelInfo>>,
}

impl MemoryChannelRegistry {
    /// Create a new in-memory channel registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a channel for testing.
    pub fn add_channel(&self, info: ChannelInfo) {
        let mut channels = self.channels.lock().unwrap();
        channels.insert(info.channel_id, info);
    }

    /// Remove a channel.
    pub fn remove_channel(&self, channel_id: &[u8; 32]) {
        let mut channels = self.channels.lock().unwrap();
        channels.remove(channel_id);
    }

    /// Update channel usability.
    pub fn set_usable(&self, channel_id: &[u8; 32], usable: bool) {
        let mut channels = self.channels.lock().unwrap();
        if let Some(info) = channels.get_mut(channel_id) {
            info.is_usable = usable;
        }
    }

    /// Update channel balance.
    pub fn set_balance(&self, channel_id: &[u8; 32], balance_msat: u64) {
        let mut channels = self.channels.lock().unwrap();
        if let Some(info) = channels.get_mut(channel_id) {
            info.balance_msat = balance_msat;
        }
    }
}

impl ChannelRegistry for MemoryChannelRegistry {
    fn partner_for_channel(&self, channel_id: [u8; 32]) -> Option<PublicKey> {
        let channels = self.channels.lock().unwrap();
        channels.get(&channel_id).map(|c| c.counterparty)
    }

    fn channels_with_peer(&self, peer: PublicKey) -> Vec<[u8; 32]> {
        let channels = self.channels.lock().unwrap();
        channels
            .iter()
            .filter(|(_, info)| info.counterparty == peer)
            .map(|(id, _)| *id)
            .collect()
    }

    fn channel_is_usable(&self, channel_id: [u8; 32]) -> bool {
        let channels = self.channels.lock().unwrap();
        channels
            .get(&channel_id)
            .map(|c| c.is_usable)
            .unwrap_or(false)
    }

    fn channel_balance_msat(&self, channel_id: [u8; 32]) -> Option<u64> {
        let channels = self.channels.lock().unwrap();
        channels.get(&channel_id).map(|c| c.balance_msat)
    }
}

impl ChannelOperations for MemoryChannelRegistry {
    fn list_channels_with_counterparty(&self, counterparty: &PublicKey) -> Vec<CoreChannelInfo> {
        let channels = self.channels.lock().unwrap();
        channels
            .values()
            .filter(|c| c.counterparty == *counterparty)
            .cloned()
            .map(|c| c.into())
            .collect()
    }

    fn list_channels(&self) -> Vec<CoreChannelInfo> {
        let channels = self.channels.lock().unwrap();
        channels.values().cloned().map(|c| c.into()).collect()
    }

    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        _counterparty: &PublicKey,
        _reason: &str,
    ) -> Result<(), String> {
        let mut channels = self.channels.lock().unwrap();
        if channels.remove(channel_id).is_some() {
            Ok(())
        } else {
            Err("Channel not found".to_string())
        }
    }
}

// ============================================================================
// LDK Channel Operations
// ============================================================================

/// LDK-based channel operations for Bitcoin Deposits protocol.
///
/// This implementation wraps callbacks that query the ChannelManager.
pub struct LdkChannelOperations {
    /// Callback to get all channels
    get_channels: Box<dyn Fn() -> Vec<ChannelInfo> + Send + Sync>,
    /// Callback to force-close a channel
    force_close: Box<dyn Fn(&[u8; 32], &PublicKey, &str) -> Result<(), String> + Send + Sync>,
}

impl LdkChannelOperations {
    /// Create a new channel operations with callbacks.
    pub fn new<G, F>(get_channels: G, force_close: F) -> Self
    where
        G: Fn() -> Vec<ChannelInfo> + Send + Sync + 'static,
        F: Fn(&[u8; 32], &PublicKey, &str) -> Result<(), String> + Send + Sync + 'static,
    {
        Self {
            get_channels: Box::new(get_channels),
            force_close: Box::new(force_close),
        }
    }
}

impl ChannelOperations for LdkChannelOperations {
    fn list_channels_with_counterparty(&self, counterparty: &PublicKey) -> Vec<CoreChannelInfo> {
        let channels = (self.get_channels)();
        channels
            .into_iter()
            .filter(|c| c.counterparty == *counterparty)
            .map(|c| c.into())
            .collect()
    }

    fn list_channels(&self) -> Vec<CoreChannelInfo> {
        let channels = (self.get_channels)();
        channels.into_iter().map(|c| c.into()).collect()
    }

    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counterparty: &PublicKey,
        reason: &str,
    ) -> Result<(), String> {
        (self.force_close)(channel_id, counterparty, reason)
    }
}

// ============================================================================
// LDK Reserves Operations
// ============================================================================

/// LDK-based reserves operations for Bitcoin Deposits protocol.
///
/// This implementation wraps callbacks that interact with the ChannelManager's
/// reserves functionality.
pub struct LdkReservesOperations {
    /// Callback to update local reserves
    update_reserves: Box<dyn Fn(&PublicKey, &[u8; 32], u64, [u8; 32]) -> Result<(), String> + Send + Sync>,
    /// Callback to get committed reserves hash
    get_committed_hash: Box<dyn Fn(&PublicKey, &[u8; 32]) -> Option<[u8; 32]> + Send + Sync>,
    /// Callback to check for pending reserves
    has_pending: Box<dyn Fn(&PublicKey, &[u8; 32]) -> bool + Send + Sync>,
    /// Callback to get both reserves hashes
    get_both_hashes: Box<dyn Fn(&PublicKey) -> (Option<[u8; 32]>, Option<[u8; 32]>) + Send + Sync>,
}

impl LdkReservesOperations {
    /// Create a new reserves operations with callbacks.
    pub fn new<U, G, H, B>(
        update_reserves: U,
        get_committed_hash: G,
        has_pending: H,
        get_both_hashes: B,
    ) -> Self
    where
        U: Fn(&PublicKey, &[u8; 32], u64, [u8; 32]) -> Result<(), String> + Send + Sync + 'static,
        G: Fn(&PublicKey, &[u8; 32]) -> Option<[u8; 32]> + Send + Sync + 'static,
        H: Fn(&PublicKey, &[u8; 32]) -> bool + Send + Sync + 'static,
        B: Fn(&PublicKey) -> (Option<[u8; 32]>, Option<[u8; 32]>) + Send + Sync + 'static,
    {
        Self {
            update_reserves: Box::new(update_reserves),
            get_committed_hash: Box::new(get_committed_hash),
            has_pending: Box::new(has_pending),
            get_both_hashes: Box::new(get_both_hashes),
        }
    }
}

impl ReservesOperations for LdkReservesOperations {
    fn update_local_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        ledger_hash: [u8; 32],
    ) -> Result<(), String> {
        (self.update_reserves)(counterparty, channel_id, reserves_sats, ledger_hash)
    }

    fn get_committed_reserves_hash(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> Option<[u8; 32]> {
        (self.get_committed_hash)(counterparty, channel_id)
    }

    fn has_pending_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> bool {
        (self.has_pending)(counterparty, channel_id)
    }

    fn get_reserves_hashes(
        &self,
        counterparty: &PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        (self.get_both_hashes)(counterparty)
    }
}

/// Simple in-memory reserves operations for testing.
#[derive(Default)]
pub struct MemoryReservesOperations {
    /// Map of (counterparty, channel_id) -> (reserves_sats, ledger_hash, committed)
    reserves: Mutex<HashMap<(PublicKey, [u8; 32]), (u64, [u8; 32], bool)>>,
}

impl MemoryReservesOperations {
    /// Create a new in-memory reserves operations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark reserves as committed for testing
    pub fn commit_reserves(&self, counterparty: &PublicKey, channel_id: &[u8; 32]) {
        let mut reserves = self.reserves.lock().unwrap();
        if let Some(entry) = reserves.get_mut(&(*counterparty, *channel_id)) {
            entry.2 = true;
        }
    }
}

impl ReservesOperations for MemoryReservesOperations {
    fn update_local_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        ledger_hash: [u8; 32],
    ) -> Result<(), String> {
        let mut reserves = self.reserves.lock().unwrap();
        reserves.insert((*counterparty, *channel_id), (reserves_sats, ledger_hash, false));
        Ok(())
    }

    fn get_committed_reserves_hash(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let reserves = self.reserves.lock().unwrap();
        reserves
            .get(&(*counterparty, *channel_id))
            .filter(|(_, _, committed)| *committed)
            .map(|(_, hash, _)| *hash)
    }

    fn has_pending_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> bool {
        let reserves = self.reserves.lock().unwrap();
        reserves
            .get(&(*counterparty, *channel_id))
            .map(|(_, _, committed)| !committed)
            .unwrap_or(false)
    }

    fn get_reserves_hashes(
        &self,
        counterparty: &PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        let reserves = self.reserves.lock().unwrap();
        // Find local reserves for this counterparty
        let local = reserves
            .iter()
            .find(|((cp, _), _)| cp == counterparty)
            .filter(|(_, (_, _, committed))| *committed)
            .map(|(_, (_, hash, _))| *hash);
        // Remote would need to be tracked separately - return None for testing
        (local, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_memory_registry_basic() {
        let registry = MemoryChannelRegistry::new();
        let peer = test_pubkey();
        let channel_id = [42u8; 32];

        // Add channel
        registry.add_channel(ChannelInfo {
            channel_id,
            counterparty: peer,
            is_usable: true,
            balance_msat: 1_000_000,
            funding_txid: None,
            funding_vout: None,
            channel_value_satoshis: 100_000,
        });

        // Query
        assert_eq!(registry.partner_for_channel(channel_id), Some(peer));
        assert_eq!(registry.channels_with_peer(peer), vec![channel_id]);
        assert!(registry.channel_is_usable(channel_id));
        assert_eq!(registry.channel_balance_msat(channel_id), Some(1_000_000));

        // Remove
        registry.remove_channel(&channel_id);
        assert_eq!(registry.partner_for_channel(channel_id), None);
    }

    #[test]
    fn test_memory_registry_multiple_channels() {
        let registry = MemoryChannelRegistry::new();
        let peer1 = test_pubkey();
        let peer2 = test_pubkey_2();

        registry.add_channel(ChannelInfo {
            channel_id: [1u8; 32],
            counterparty: peer1,
            is_usable: true,
            balance_msat: 100_000,
            funding_txid: None,
            funding_vout: None,
            channel_value_satoshis: 100_000,
        });

        registry.add_channel(ChannelInfo {
            channel_id: [2u8; 32],
            counterparty: peer1,
            is_usable: false,
            balance_msat: 200_000,
            funding_txid: None,
            funding_vout: None,
            channel_value_satoshis: 100_000,
        });

        registry.add_channel(ChannelInfo {
            channel_id: [3u8; 32],
            counterparty: peer2,
            is_usable: true,
            balance_msat: 300_000,
            funding_txid: None,
            funding_vout: None,
            channel_value_satoshis: 100_000,
        });

        // peer1 has 2 channels
        let channels = registry.channels_with_peer(peer1);
        assert_eq!(channels.len(), 2);

        // peer2 has 1 channel
        let channels = registry.channels_with_peer(peer2);
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], [3u8; 32]);
    }

    #[test]
    fn test_memory_registry_update() {
        let registry = MemoryChannelRegistry::new();
        let channel_id = [42u8; 32];

        registry.add_channel(ChannelInfo {
            channel_id,
            counterparty: test_pubkey(),
            is_usable: true,
            balance_msat: 1_000_000,
            funding_txid: None,
            funding_vout: None,
            channel_value_satoshis: 100_000,
        });

        // Update usability
        assert!(registry.channel_is_usable(channel_id));
        registry.set_usable(&channel_id, false);
        assert!(!registry.channel_is_usable(channel_id));

        // Update balance
        assert_eq!(registry.channel_balance_msat(channel_id), Some(1_000_000));
        registry.set_balance(&channel_id, 500_000);
        assert_eq!(registry.channel_balance_msat(channel_id), Some(500_000));
    }

    #[test]
    fn test_callback_registry() {
        let channels = vec![
            ChannelInfo {
                channel_id: [1u8; 32],
                counterparty: test_pubkey(),
                is_usable: true,
                balance_msat: 100_000,
                funding_txid: None,
                funding_vout: None,
                channel_value_satoshis: 100_000,
            },
            ChannelInfo {
                channel_id: [2u8; 32],
                counterparty: test_pubkey_2(),
                is_usable: true,
                balance_msat: 200_000,
                funding_txid: None,
                funding_vout: None,
                channel_value_satoshis: 100_000,
            },
        ];

        let registry = LdkChannelRegistry::new(move || channels.clone());

        assert_eq!(registry.partner_for_channel([1u8; 32]), Some(test_pubkey()));
        assert_eq!(registry.partner_for_channel([2u8; 32]), Some(test_pubkey_2()));
        assert_eq!(registry.partner_for_channel([3u8; 32]), None);
    }
}
