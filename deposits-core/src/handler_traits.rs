// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Handler Extension Traits
//!
//! This module defines traits that protocol handlers must implement to provide
//! various deposit operations. These traits are implemented by ldk-node's
//! `DepositsHandler` but can be implemented by any handler implementation.
//!
//! The traits are organized by operation category:
//! - [`CollateralOperations`] - Query quorum members and attestations
//! - [`DepositOperations`] - CRUD operations on deposits
//! - [`LedgerOperations`] - Query ledger state and hashes
//! - [`PaymentTracking`] - Track deposit invoice payments
//! - [`RecoveryOperations`] - Handle force-close recovery process
//! - [`ReservesOperations`] - Query reserves status

use bitcoin::secp256k1::PublicKey;

use crate::error::DepositsError;
use crate::handler_types::CollateralInfo;
use crate::types::{DepositId, ReservesStatus};

// ============================================================================
// Collateral Operations
// ============================================================================

/// Extension trait for collateral query operations
pub trait CollateralOperations {
    /// Get collateral info for a ledger partner
    fn get_collateral_info(&self, partner_node_id: PublicKey) -> Option<CollateralInfo>;

    /// Get the list of quorum members for a channel
    fn get_quorum_members(&self, partner_node_id: PublicKey) -> Vec<PublicKey>;

    /// Check if a node is a quorum member for a channel
    fn is_quorum_member(&self, partner_node_id: PublicKey, potential_collateral: PublicKey)
        -> bool;

    /// Get the total available collateral for a channel
    fn get_total_available_collateral(&self, partner_node_id: PublicKey) -> u64;
}

// ============================================================================
// Deposit Operations
// ============================================================================

/// Extension trait for deposit CRUD operations
pub trait DepositOperations {
    /// List all deposit IDs across all ledgers
    fn list_deposits(&self) -> Result<Vec<DepositId>, DepositsError>;

    /// List deposits matching a specific deposit_id
    fn list_deposits_for_deposit_id(
        &self,
        deposit_id: DepositId,
    ) -> Result<Vec<DepositId>, DepositsError>;

    /// Get the available balance for a deposit (balance - locked)
    fn get_deposit_balance(&self, deposit_id: DepositId) -> Result<u64, DepositsError>;

    /// Get the descriptor for a deposit by deposit_id
    fn get_deposit_descriptor(&self, deposit_id: DepositId) -> Result<String, DepositsError>;

    /// Find a deposit by payment_hash (from an invoice)
    /// Returns (reserves_id, deposit_id, invoice_amount) if found
    fn find_deposit_by_payment_hash(
        &self,
        payment_hash: &[u8; 32],
    ) -> Option<(String, DepositId, u64)>;

    /// Get all deposit_ids with positive balances
    fn get_active_depositors(&self) -> Vec<DepositId>;

    /// Get total deposit balances for a partner
    fn get_total_deposit_balances(&self, partner_node_id: PublicKey) -> Option<u64>;

    /// Get detailed deposit info for a partner
    /// Returns Vec of (deposit_id, balance, locked_balance)
    fn get_deposits_for_partner(
        &self,
        partner_node_id: PublicKey,
    ) -> Option<Vec<(DepositId, u64, u64)>>;

    /// Get max outstanding invoice amount for a channel
    fn get_max_outstanding_invoice_amount(&self, partner_node_id: PublicKey) -> Option<u64>;
}

// ============================================================================
// Ledger Operations
// ============================================================================

/// Extension trait for ledger query operations
pub trait LedgerOperations {
    /// Get the current ledger hash for a partner (where we are operator)
    fn get_ledger_hash(&self, partner_node_id: PublicKey) -> Result<[u8; 32], DepositsError>;

    /// Get both local and remote committed ledger hashes for a channel partner
    /// Returns (local_hash, remote_hash)
    fn get_ledger_hashes(&self, partner_node_id: PublicKey)
        -> (Option<[u8; 32]>, Option<[u8; 32]>);

    /// Get committed ledger hashes directly from the channel state
    /// Returns (local_hash, remote_hash)
    fn get_committed_ledger_hashes_from_channel(
        &self,
        counterparty_node_id: PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>);

    /// Validate that a ledger hash is valid for reserves (Porcupine Dance check)
    fn validate_ledger_hash_for_reserves(
        &self,
        counterparty_node_id: &PublicKey,
        ledger_hash: &[u8; 32],
    ) -> bool;

    /// Get the ledger sequence number for a partner
    fn get_ledger_sequence(&self, partner_node_id: PublicKey) -> Result<u64, DepositsError>;

    /// Check if we have a ledger with this partner (as operator)
    fn has_ledger_with(&self, partner_node_id: PublicKey) -> bool;

    /// List all reserves_ids where we are the operator
    fn list_operator_ledgers(&self) -> Vec<String>;

    /// List all operators where we are the partner (reserves)
    fn list_partner_ledgers(&self) -> Vec<PublicKey>;
}

// ============================================================================
// Payment Tracking
// ============================================================================

/// Extension trait for tracking deposit invoice payments
pub trait PaymentTracking {
    /// Check if a payment hash is registered as a deposit invoice payment
    /// Returns true if this payment_hash was registered when an invoice was cosigned
    fn is_deposit_invoice_payment(&self, payment_hash: &[u8; 32]) -> bool;

    /// Register a payment hash as belonging to a deposit invoice
    /// This MUST be called when an invoice is cosigned so we can validate
    /// payments before accepting them
    fn register_deposit_invoice(
        &self,
        payment_hash: [u8; 32],
        reserves_id: PublicKey,
        deposit_pubkey: PublicKey,
        invoice_id: String,
        bolt11: String,
    );

    /// Get the bolt11 invoice string for a payment hash if it's a registered deposit invoice
    fn get_deposit_invoice_bolt11(&self, payment_hash: &[u8; 32]) -> Option<String>;

    /// Get the full deposit info for a payment hash
    /// Returns (reserves_id, deposit_pubkey, invoice_id, bolt11) if found
    fn get_deposit_for_payment(
        &self,
        payment_hash: &[u8; 32],
    ) -> Option<(PublicKey, PublicKey, String, String)>;

    /// Unregister a deposit invoice (e.g., after payment or expiry)
    fn unregister_deposit_invoice(&self, payment_hash: &[u8; 32]);

    /// Remove all payment registrations for a specific partner (used during channel close cleanup)
    fn cleanup_payments_for_partner(&self, partner_node_id: PublicKey);
}

// ============================================================================
// Recovery Operations
// ============================================================================

/// Extension trait for force-close recovery operations
pub trait RecoveryOperations {
    /// Start tracking a recovery process when a force close is detected
    fn start_recovery_tracking(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        force_close_block: u32,
        force_close_txid: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Called when the entropy block arrives (6 blocks after force close confirmation)
    fn on_recovery_entropy_block(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        entropy_block_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Initiate a claim for a non-compliant recovery and request signatures from voters
    fn initiate_claim_and_request_signatures(
        &self,
        operator: PublicKey,
        partner: PublicKey,
    ) -> Result<(), String>;

    /// Submit our vote for a recovery process
    fn submit_recovery_vote(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        conforming: bool,
        spend_signature: Option<[u8; 64]>,
    ) -> Result<(), String>;

    /// Get the current recovery phase for a ledger
    fn get_recovery_phase(&self, operator: PublicKey, partner: PublicKey) -> Option<String>;

    /// Check if a ledger is in recovery mode
    fn is_in_recovery(&self, operator: PublicKey, partner: PublicKey) -> bool;
}

// ============================================================================
// Reserves Query Operations
// ============================================================================

/// Extension trait for reserves query operations
///
/// Note: This is separate from the `ReservesOperations` adapter trait in `traits.rs`
/// which handles low-level commitment transaction updates. This trait provides
/// query methods for reserves status.
pub trait ReservesQueryOps {
    /// Get the current reserves status for a channel
    fn get_channel_reserves_status(
        &self,
        partner_node_id: PublicKey,
    ) -> Result<ReservesStatus, DepositsError>;

    /// Get the reserves amount from our ledger
    fn get_channel_reserves_amount(&self, partner_node_id: PublicKey) -> Option<u64>;

    /// Get the commitment transaction reserves amount (from partner's perspective)
    fn get_commitment_tx_reserves_amount(&self, operator_node_id: PublicKey) -> Option<u64>;

    /// Get both local and remote reserves amounts
    /// Returns (local_reserves, remote_reserves)
    fn get_channel_reserves(&self, counterparty_node_id: PublicKey) -> (Option<u64>, Option<u64>);
}
