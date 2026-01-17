// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Commitment transaction operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for enhancing Lightning commitment transactions
//! with reserves outputs and ledger hash attestations.
//!
//! NOTE: This is currently stubbed out pending migration of CommitmentTransactionEnhancer
//! and ReservesOutputManager to deposits-ldk.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Trigger an actual Lightning commitment transaction update with reserves output and ledger hash.
    ///
    /// NOTE: This is currently a stub. The actual commitment enhancement functionality
    /// depends on CommitmentTransactionEnhancer and ReservesOutputManager which need
    /// to be migrated from ldk-node.
    pub(super) fn trigger_commitment_transaction_update(
        &self,
        _partner_node_id: PublicKey,
        _ledger_hash: [u8; 32],
        _commitment_number: u64,
    ) -> Result<(), DepositsError> {
        // TODO: Migrate CommitmentTransactionEnhancer and ReservesOutputManager
        // For now, this is a no-op stub that allows compilation
        Ok(())
    }
}
