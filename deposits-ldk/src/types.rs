// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Type aliases for common types used in deposits-ldk.

use lightning::util::persist::KVStore;
use crate::wire::message_types::*;

/// Dynamic storage type - wraps LDK's KVStore trait object
pub type DynStore = dyn KVStore + Sync + Send;

/// HashStrategy determines how to calculate the expected consensus hash
/// for message types that require commitment transaction synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashStrategy {
    /// Use the current committed hash (after the operation is applied).
    /// Used for amount-changing operations (ReservesAdd, ReservesToReserves, etc.)
    /// where the reserves amount in the commitment must match ledger state.
    CurrentCommitted,

    /// Predict the hash that will result from the operation being applied.
    /// Used for operations where the commitment must contain the post-op state.
    /// Example: ReceivingCreditPayment - commit predicted hash, then apply credit.
    PredictedAfterOp,

    /// No synchronization needed. The hash will catch up on next sync operation.
    /// Used for operations that don't immediately affect reserves (e.g., LedgerAddDeposit).
    None,
}

impl HashStrategy {
    /// Determine the hash strategy for a given message type.
    /// Returns (needs_reserves_update, strategy)
    pub fn for_message_type(msg_type: u16) -> (bool, HashStrategy) {
        match msg_type {
            // Amount-changing operations - sync after applying
            RESERVES_ADD_OUTPUT | RESERVES_INCREASE | COLLATERAL_INCREASE => {
                (true, HashStrategy::CurrentCommitted)
            },
            // Credit must be in committed hash - predict before applying
            RECEIVING_CREDIT_PAYMENT => {
                (true, HashStrategy::PredictedAfterOp)
            },
            // Everything else - no sync needed (catches up lazily)
            _ => (false, HashStrategy::None),
        }
    }

    /// Check if this strategy requires synchronization
    pub fn requires_sync(&self) -> bool {
        !matches!(self, HashStrategy::None)
    }
}
