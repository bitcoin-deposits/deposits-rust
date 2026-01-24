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
    // V2 Core Message Types
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,

    // V1 Legacy Message Types
    // Reserves operations
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE,
    RESERVES_DECREASE, RESERVES_UPDATE_OUTPUT,
    UPDATE_RESERVES, ACCEPT_RESERVES,

    // Collateral operations
    COLLATERAL_INCREASE, COLLATERAL_DECREASE,
    COLLATERAL_ATTESTATION, COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE,

    // Deposit operations
    DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE,
    DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER, DEPOSIT_FULFILL_TRANSFER,

    // Ledger lifecycle
    LEDGER_CLOSE, CHANNEL_CLOSE_TOMBSTONE,

    // Maintenance
    MAINTENANCE_FEE_COLLECT,

    // Receiving (incoming payments)
    RECEIVING_COSIGN_INVOICE, RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT,

    // Sending (outgoing payments)
    SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT, SENDING_FULFILL_PAYMENT,

    // Signed updates and sync
    SIGNED_UPDATE, SYNC_REQUEST,

    // Ledger establishment
    LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE,

    // Acknowledgment
    ACK,

    // Quorum operations
    QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE, QUORUM_STATE_SYNC,
    QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,

    // Recovery operations
    RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE, RECOVERY_CLAIM_COMPLETE,

    // Relay (NWC)
    RELAY_NWC_REQUEST, RELAY_NWC_RESPONSE, RELAY_NWC_DELIVERY_PROOF,

    // Collections
    ALL_V1_MESSAGE_TYPES, ALL_V2_MESSAGE_TYPES, MESSAGES_REQUIRING_ACK,

    // Utility functions
    is_deposits_message_type, requires_acknowledgment, get_message_category,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_message_types_are_odd() {
        // Per BOLT 1: odd types MAY be ignored if not understood
        for &t in ALL_V1_MESSAGE_TYPES {
            assert!(t & 1 == 1, "V1 message type 0x{:04X} is not odd", t);
        }
        for &t in ALL_V2_MESSAGE_TYPES {
            assert!(t & 1 == 1, "V2 message type 0x{:04X} is not odd", t);
        }
    }

    #[test]
    fn test_is_deposits_message_type() {
        // V2 types
        assert!(is_deposits_message_type(LEDGER_UPDATE));
        assert!(is_deposits_message_type(HANDSHAKE));

        // V1 types
        assert!(is_deposits_message_type(DEPOSIT_OPEN));
        assert!(is_deposits_message_type(RESERVES_ADD_OUTPUT));

        // Not a deposits type
        assert!(!is_deposits_message_type(0x0001));
        assert!(!is_deposits_message_type(0xFFFF));
    }

    #[test]
    fn test_requires_acknowledgment() {
        assert!(requires_acknowledgment(DEPOSIT_OPEN));
        assert!(requires_acknowledgment(LEDGER_UPDATE));
        assert!(requires_acknowledgment(HANDSHAKE));

        assert!(!requires_acknowledgment(ACK));
        assert!(!requires_acknowledgment(LEDGER_UPDATE_RESPONSE));
    }

    #[test]
    fn test_get_message_category() {
        assert_eq!(get_message_category(DEPOSIT_OPEN), Some("deposit"));
        assert_eq!(get_message_category(RESERVES_ADD_OUTPUT), Some("reserves"));
        assert_eq!(get_message_category(COLLATERAL_INCREASE), Some("collateral"));
        assert_eq!(get_message_category(LEDGER_UPDATE), Some("ledger"));
        assert_eq!(get_message_category(0xFFFF), None);
    }
}
