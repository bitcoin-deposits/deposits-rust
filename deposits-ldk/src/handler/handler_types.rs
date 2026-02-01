// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Handler-specific types for the Bitcoin Deposits protocol.
//!
//! This module re-exports handler types from deposits-core and provides
//! LDK-specific variants where needed.

use bitcoin::secp256k1::PublicKey;

// Re-export most types from deposits-core
pub use deposits_core::handler_types::{
    CosignedInvoice,
    VoteRoundState,
    ProtocolStats,
    QuorumMemberInfo,
    CollateralInfo,
};

// These types use std::time::SystemTime for LDK integration compatibility
// deposits-core uses u64 timestamps for portability

/// Ledger state summary for API responses
///
/// This is a lightweight summary of ledger state, different from the full LedgerState
/// which contains all deposits, invoices, and history.
#[derive(Clone, Debug)]
pub struct LedgerSummary {
    /// The partner node ID (uniquely identifies the ledger together with operator)
    pub partner_node_id: PublicKey,
    /// Total deposit balance in satoshis
    pub total_deposits: u64,
    /// Total reserves amount in satoshis
    pub total_reserves: u64,
    /// Timestamp of last activity
    pub last_activity: std::time::SystemTime,
}

/// Reserves status summary for API responses
#[derive(Clone, Debug)]
pub struct ReservesSummary {
    /// Current confirmed reserves amount in satoshis
    pub current_amount: u64,
    /// Pending reserves amount in satoshis
    pub pending_amount: u64,
    /// Timestamp of last update
    pub last_update: std::time::SystemTime,
}
