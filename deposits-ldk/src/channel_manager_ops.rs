// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Channel Manager Operations Trait
//!
//! This module defines the `ChannelManagerOps` trait that abstracts all the
//! channel manager operations needed by the Bitcoin Deposits handler.
//!
//! The trait allows deposits-ldk to be independent of ldk-node's ChannelManager
//! while still being able to use its functionality when wired up.

use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;
use lightning::ln::types::ChannelId;

/// Channel details for reserves operations
#[derive(Clone, Debug)]
pub struct ChannelDetails {
    /// The channel ID
    pub channel_id: ChannelId,
    /// Funding transaction outpoint (txid, vout)
    pub funding_txo: Option<(bitcoin::Txid, u32)>,
    /// Counterparty node public key
    pub counterparty_node_id: PublicKey,
    /// Whether the channel is usable
    pub is_usable: bool,
    /// Channel capacity in satoshis
    pub channel_value_satoshis: u64,
    /// Our balance in millisatoshis
    pub balance_msat: u64,
    /// Local reserves info (amount in sats, ledger hash)
    pub local_reserves: Option<(u64, [u8; 32])>,
    /// Remote reserves info (amount in sats, ledger hash)
    pub remote_reserves: Option<(u64, [u8; 32])>,
}

/// Trait for channel manager operations needed by the deposits handler.
///
/// This trait abstracts LDK's ChannelManager so that:
/// 1. deposits-ldk can compile independently of ldk-node
/// 2. ldk-node can provide the real implementation at runtime
/// 3. Tests can use mock implementations
pub trait ChannelManagerOps: Send + Sync {
    /// List all channels with a specific counterparty
    fn list_channels_with_counterparty(&self, node_id: &PublicKey) -> Vec<ChannelDetails>;

    /// List all channels
    fn list_channels(&self) -> Vec<ChannelDetails>;

    /// Get the current best block height
    fn current_best_block_height(&self) -> u32;

    /// Send an update_reserves message to a peer
    ///
    /// This updates the reserves commitment for a channel.
    fn send_update_reserves(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        reserves_sats: u64,
        script_pubkey: ScriptBuf,
        holder_ledger_hash: [u8; 32],
        remote_ledger_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Get the currently committed local reserves ledger hash
    fn get_channel_local_reserves_ledger_hash(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Option<[u8; 32]>;

    /// Check if there are pending (uncommitted) local reserves updates
    fn has_pending_local_reserves(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> bool;

    /// Force close a channel with the latest transaction
    fn force_close_broadcasting_latest_txn(
        &self,
        channel_id: &ChannelId,
        counterparty_node_id: &PublicKey,
        reason: String,
    ) -> Result<(), String>;

    /// Get the remote reserves amount for a channel
    fn get_channel_remote_reserves_amount(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Option<u64>;

    /// Get the local reserves amount for a channel
    fn get_channel_local_reserves_amount(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Option<u64>;
}

/// A null implementation of ChannelManagerOps that does nothing.
/// Used when channel manager is not set.
pub struct NullChannelManager;

impl ChannelManagerOps for NullChannelManager {
    fn list_channels_with_counterparty(&self, _node_id: &PublicKey) -> Vec<ChannelDetails> {
        Vec::new()
    }

    fn list_channels(&self) -> Vec<ChannelDetails> {
        Vec::new()
    }

    fn current_best_block_height(&self) -> u32 {
        0
    }

    fn send_update_reserves(
        &self,
        _node_id: &PublicKey,
        _channel_id: &ChannelId,
        _reserves_sats: u64,
        _script_pubkey: ScriptBuf,
        _holder_ledger_hash: [u8; 32],
        _remote_ledger_hash: [u8; 32],
    ) -> Result<(), String> {
        Ok(())
    }

    fn get_channel_local_reserves_ledger_hash(
        &self,
        _node_id: &PublicKey,
        _channel_id: &ChannelId,
    ) -> Option<[u8; 32]> {
        None
    }

    fn has_pending_local_reserves(
        &self,
        _node_id: &PublicKey,
        _channel_id: &ChannelId,
    ) -> bool {
        false
    }

    fn force_close_broadcasting_latest_txn(
        &self,
        _channel_id: &ChannelId,
        _counterparty_node_id: &PublicKey,
        _reason: String,
    ) -> Result<(), String> {
        Ok(())
    }

    fn get_channel_remote_reserves_amount(
        &self,
        _node_id: &PublicKey,
        _channel_id: &ChannelId,
    ) -> Option<u64> {
        None
    }

    fn get_channel_local_reserves_amount(
        &self,
        _node_id: &PublicKey,
        _channel_id: &ChannelId,
    ) -> Option<u64> {
        None
    }
}
