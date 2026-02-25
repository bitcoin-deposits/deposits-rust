// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wire Protocol Message Type Constants
//!
//! Re-exports message type constants from deposits-core for backwards compatibility.
//! All message types use odd numbers per BOLT 1 "it's OK to be odd" rule for safe ignorability.

// Re-export all message type constants from deposits-core
pub use deposits_core::messages::{
    // Envelope Message Types (used for wire transmission)
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,

    // Operation Message Types (used in SignedLedgerUpdate.message_type)
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT,
    RESERVES_ROTATE,
    QUORUM_JOIN,
    DEPOSIT_OPEN,
    LEDGER_CLOSE, CHANNEL_CLOSE_TOMBSTONE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_message_types_are_odd() {
        // Per BOLT 1: odd types MAY be ignored if not understood
        let all_types: &[u16] = &[
            LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
            HANDSHAKE, HANDSHAKE_RESPONSE,
            SYNC, SYNC_RESPONSE,
            RECOVERY, RECOVERY_RESPONSE,
            COORDINATION, COORDINATION_RESPONSE,
            RELAY, RELAY_RESPONSE,
            RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT,
            RESERVES_ROTATE, QUORUM_JOIN,
            DEPOSIT_OPEN, LEDGER_CLOSE, CHANNEL_CLOSE_TOMBSTONE,
        ];
        for &t in all_types {
            assert!(t & 1 == 1, "Message type 0x{:04X} is not odd", t);
        }
    }
}
