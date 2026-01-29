// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Handler-specific types for the Bitcoin Deposits protocol.
//!
//! This module contains types used by protocol handlers that are specific to the
//! handler implementation, including statistics, summaries, and state tracking.

use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;

// ============================================================================
// Pending Operation Tracking
// ============================================================================

/// Details of a pending transfer operation (deposit-to-deposit within ledger)
///
/// Tracks transfers that have been locked but not yet fulfilled or failed.
/// This is used for the lock-fail-fulfill pattern in deposit transfers.
#[derive(Clone, Debug)]
pub struct PendingTransfer {
    /// The deposit this transfer is from
    pub deposit_pubkey: PublicKey,
    /// Amount being transferred in satoshis
    pub amount: u64,
    /// Unix timestamp when the transfer was locked
    pub locked_at: u64,
    /// Unique identifier for this transfer
    pub transfer_id: [u8; 32],
}

/// Details of a pending payment operation (outbound Lightning payment)
///
/// Tracks payments that have been locked but not yet fulfilled or failed.
/// This is used for the lock-fail-fulfill pattern in outbound payments.
#[derive(Clone, Debug)]
pub struct PendingPayment {
    /// The deposit this payment is from
    pub deposit_pubkey: PublicKey,
    /// Amount being paid in satoshis
    pub amount: u64,
    /// Unix timestamp when the payment was locked
    pub locked_at: u64,
    /// Unique identifier for this payment (typically payment_hash)
    pub payment_id: [u8; 32],
}

// ============================================================================
// Protocol State Types
// ============================================================================

/// Cosigned invoice record stored by partners for fraud proof validation.
/// Kept in memory (not in ledger) to prevent spam attacks.
/// Cleaned up after expiration + grace period.
#[derive(Clone, Debug)]
pub struct CosignedInvoice {
    /// The deposit this invoice is assigned to
    pub deposit_pubkey: PublicKey,
    /// Payment hash (also part of the key)
    pub payment_hash: [u8; 32],
    /// Invoice amount in satoshis
    pub amount: u64,
    /// Expiration timestamp (Unix seconds)
    pub expires: u64,
    /// Cosignature we generated
    pub cosignature: Vec<u8>,
}

/// State for an active vote round (collecting signatures for cooperative reserve spending)
#[derive(Debug, Clone)]
pub struct VoteRoundState {
    /// The operator's public key
    pub operator_id: PublicKey,
    /// The partner's public key
    pub reserves_id: PublicKey,
    /// Sequence number for this vote round
    pub sequence_number: u64,
    /// Hash of the ledger state being voted on
    pub state_hash: [u8; 32],
    /// Amount of reserves being claimed
    pub claimed_reserves: u64,
    /// Reserves UTXO outpoint (txid:vout)
    pub reserves_outpoint: Vec<u8>,
    /// Destination script for reserves payout
    pub destination_script: Vec<u8>,
    /// Fee rate for spend transaction
    pub fee_rate_sat_vbyte: u64,
    /// Required threshold for this round
    pub threshold: usize,
    /// Collected votes: voter_pubkey -> (voted_conforming, spend_signature if conforming)
    pub votes: HashMap<PublicKey, (bool, Option<[u8; 64]>)>,
    /// Whether we've already broadcast the finalized tx
    pub tx_broadcast: bool,
    /// Timestamp when this round was created
    pub created_at: u64,
}

impl VoteRoundState {
    /// Count conforming votes
    pub fn conforming_vote_count(&self) -> usize {
        self.votes.values().filter(|(v, _)| *v).count()
    }

    /// Check if threshold is reached
    pub fn threshold_reached(&self) -> bool {
        self.conforming_vote_count() >= self.threshold
    }

    /// Get all spend signatures from conforming votes
    pub fn collect_spend_signatures(&self) -> Vec<(PublicKey, [u8; 64])> {
        self.votes
            .iter()
            .filter_map(|(pk, (conforming, sig))| {
                if *conforming {
                    sig.map(|s| (*pk, s))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Protocol statistics
#[derive(Clone, Debug, Default)]
pub struct ProtocolStats {
    /// Number of active partners
    pub active_partners: usize,
    /// Number of pending outbound messages
    pub pending_outbound_messages: usize,
    /// Total number of ledgers
    pub total_ledgers: usize,
}

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
    /// Timestamp of last activity (Unix seconds)
    pub last_activity: u64,
}

/// Reserves status summary for API responses
#[derive(Clone, Debug, Default)]
pub struct ReservesSummary {
    /// Current confirmed reserves amount in satoshis
    pub current_amount: u64,
    /// Pending reserves amount in satoshis
    pub pending_amount: u64,
    /// Timestamp of last update (Unix seconds)
    pub last_update: u64,
}

/// Information about a single collateral partner and their attestation
#[derive(Clone, Debug)]
pub struct CollateralPartnerInfo {
    /// The collateral partner's public key
    pub pubkey: PublicKey,
    /// Amount of collateral provided in satoshis
    pub collateral_amount: u64,
    /// Block height when collateral was last updated
    pub block_height: u32,
    /// Whether we have received an attestation from this partner
    pub has_attestation: bool,
}

/// Collateral information for a ledger
#[derive(Clone, Debug, Default)]
pub struct CollateralInfo {
    /// List of collateral partners and their info
    pub collateral_partners: Vec<CollateralPartnerInfo>,
    /// Our attestation as a partner (if we are a collateral partner)
    pub partner_attestation: Option<CollateralPartnerInfo>,
    /// Total available collateral across all partners
    pub total_available_collateral: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_vote_round_state() {
        let mut state = VoteRoundState {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey(),
            sequence_number: 1,
            state_hash: [0u8; 32],
            claimed_reserves: 100000,
            reserves_outpoint: vec![],
            destination_script: vec![],
            fee_rate_sat_vbyte: 10,
            threshold: 2,
            votes: HashMap::new(),
            tx_broadcast: false,
            created_at: 0,
        };

        // No votes initially
        assert_eq!(state.conforming_vote_count(), 0);
        assert!(!state.threshold_reached());

        // Add a conforming vote
        state.votes.insert(test_pubkey(), (true, Some([0u8; 64])));
        assert_eq!(state.conforming_vote_count(), 1);
        assert!(!state.threshold_reached());

        // Add another conforming vote (different pubkey)
        let pk2 = {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };
        state.votes.insert(pk2, (true, Some([1u8; 64])));
        assert_eq!(state.conforming_vote_count(), 2);
        assert!(state.threshold_reached());

        // Collect signatures
        let sigs = state.collect_spend_signatures();
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_protocol_stats_default() {
        let stats = ProtocolStats::default();
        assert_eq!(stats.active_partners, 0);
        assert_eq!(stats.pending_outbound_messages, 0);
        assert_eq!(stats.total_ledgers, 0);
    }
}
