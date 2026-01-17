// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! V1 Wire Protocol Message Type Constants
//!
//! These constants define the message types used in the V1 wire protocol for
//! Bitcoin Deposits. All types use odd numbers per BOLT 1 "it's OK to be odd"
//! rule for safe ignorability.
//!
//! The V1 protocol uses individual message types for each operation, while
//! V2 consolidates these into `LedgerUpdate` with operation discriminants.

// ============================================================================
// V2 Core Message Types (from deposits-core)
// ============================================================================

// Re-export V2 message types from deposits-core
pub use deposits_core::messages::{
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,
};

// ============================================================================
// V1 Legacy Message Types
// ============================================================================

// Reserves operations
pub const RESERVES_ADD_OUTPUT: u16 = 0x80C1;
pub const RESERVES_REMOVE_OUTPUT: u16 = 0x80C3;
pub const RESERVES_INCREASE: u16 = 0x80B1;
pub const RESERVES_DECREASE: u16 = 0x80B3;
pub const RESERVES_UPDATE_OUTPUT: u16 = 0x80C9;

// Collateral operations
pub const COLLATERAL_INCREASE: u16 = 0x80CB;
pub const COLLATERAL_DECREASE: u16 = 0x80CD;
pub const COLLATERAL_STATUS: u16 = 0x80CF;
pub const COLLATERAL_ATTESTATION: u16 = 0x808D;
pub const COLLATERAL_ADD_PARTNER: u16 = 0x8097;
pub const COLLATERAL_REMOVE_PARTNER: u16 = 0x8099;
pub const COLLATERAL_CONSENT_REQUEST: u16 = 0x809B;
pub const COLLATERAL_CONSENT_RESPONSE: u16 = 0x809D;

// Deposit operations
pub const DEPOSIT_OPEN: u16 = 0x80D1;
pub const DEPOSIT_CLOSE: u16 = 0x80D3;
pub const DEPOSIT_UPDATE: u16 = 0x80D5;
pub const DEPOSIT_LOCK_TRANSFER: u16 = 0x80D7;
pub const DEPOSIT_FAIL_TRANSFER: u16 = 0x80D9;
pub const DEPOSIT_FULFILL_TRANSFER: u16 = 0x80DB;

// Ledger lifecycle
pub const LEDGER_CLOSE: u16 = 0x801D;
pub const CHANNEL_CLOSE_TOMBSTONE: u16 = 0x8051;

// Maintenance
pub const MAINTENANCE_FEE_COLLECT: u16 = 0x8021;

// Receiving (incoming payments)
pub const RECEIVING_COSIGN_INVOICE: u16 = 0x8031;
pub const RECEIVING_CREDIT_PAYMENT: u16 = 0x8033;
pub const UNCREDITED_PAYMENT: u16 = 0x8035;

// Sending (outgoing payments)
pub const SENDING_LOCK_PAYMENT: u16 = 0x8041;
pub const SENDING_FAIL_PAYMENT: u16 = 0x8043;
pub const SENDING_FULFILL_PAYMENT: u16 = 0x8045;

// Signed updates and sync
pub const SIGNED_UPDATE: u16 = 0x8057;
pub const SYNC_REQUEST: u16 = 0x8059;

// Ledger establishment (V1 aliases for Handshake)
pub const LEDGER_OPEN_REQUEST: u16 = 0x8061;
pub const LEDGER_OPEN_RESPONSE: u16 = 0x8063;

// Acknowledgment
pub const ACK: u16 = 0x8071;

// Quorum operations
pub const QUORUM_JOIN_REQUEST: u16 = 0x8081;
pub const QUORUM_JOIN_RESPONSE: u16 = 0x8083;
pub const QUORUM_STATE_SYNC: u16 = 0x8085;
pub const QUORUM_VOTE_REQUEST: u16 = 0x8087;
pub const QUORUM_VOTE: u16 = 0x8089;
pub const QUORUM_MEMBERSHIP_CHANGE: u16 = 0x808B;

// Recovery operations
pub const RECOVERY_VOTE: u16 = 0x808F;
pub const RECOVERY_CLAIM_REQUEST: u16 = 0x8091;
pub const RECOVERY_CLAIM_SIGNATURE: u16 = 0x8093;
pub const RECOVERY_CLAIM_COMPLETE: u16 = 0x8095;

// Relay (NWC)
pub const RELAY_NWC_REQUEST: u16 = 0x80A1;
pub const RELAY_NWC_RESPONSE: u16 = 0x80A3;
pub const RELAY_NWC_DELIVERY_PROOF: u16 = 0x80A5;

// ============================================================================
// Message Type Collections
// ============================================================================

/// All V1 message types
pub const ALL_V1_MESSAGE_TYPES: &[u16] = &[
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE,
    RESERVES_DECREASE, RESERVES_UPDATE_OUTPUT,
    COLLATERAL_INCREASE, COLLATERAL_DECREASE, COLLATERAL_STATUS,
    COLLATERAL_ATTESTATION, COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE,
    DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER, DEPOSIT_FULFILL_TRANSFER,
    LEDGER_CLOSE, CHANNEL_CLOSE_TOMBSTONE,
    MAINTENANCE_FEE_COLLECT,
    RECEIVING_COSIGN_INVOICE, RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT,
    SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT, SENDING_FULFILL_PAYMENT,
    SIGNED_UPDATE, SYNC_REQUEST,
    LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE,
    ACK,
    QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE, QUORUM_STATE_SYNC,
    QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,
    RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE, RECOVERY_CLAIM_COMPLETE,
    RELAY_NWC_REQUEST, RELAY_NWC_RESPONSE, RELAY_NWC_DELIVERY_PROOF,
];

/// All V2 message types
pub const ALL_V2_MESSAGE_TYPES: &[u16] = &[
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,
];

/// Messages that require acknowledgment
pub const MESSAGES_REQUIRING_ACK: &[u16] = &[
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE,
    RESERVES_DECREASE, RESERVES_UPDATE_OUTPUT,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE,
    DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER, DEPOSIT_FULFILL_TRANSFER,
    RECEIVING_CREDIT_PAYMENT, RECEIVING_COSIGN_INVOICE,
    SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT, SENDING_FULFILL_PAYMENT,
    COLLATERAL_INCREASE, COLLATERAL_DECREASE,
    COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE,
    MAINTENANCE_FEE_COLLECT,
    LEDGER_CLOSE, CHANNEL_CLOSE_TOMBSTONE,
    LEDGER_OPEN_REQUEST,
    LEDGER_UPDATE,
    HANDSHAKE,
];

// ============================================================================
// Message Type Utilities
// ============================================================================

/// Check if a message type is a Bitcoin Deposits protocol message
pub fn is_deposits_message_type(message_type: u16) -> bool {
    // Check V2 types
    if ALL_V2_MESSAGE_TYPES.contains(&message_type) {
        return true;
    }
    // Check V1 types
    if ALL_V1_MESSAGE_TYPES.contains(&message_type) {
        return true;
    }
    false
}

/// Check if a message type requires acknowledgment
pub fn requires_acknowledgment(message_type: u16) -> bool {
    MESSAGES_REQUIRING_ACK.contains(&message_type)
}

/// Get the message category for a V1 message type
pub fn get_message_category(message_type: u16) -> Option<&'static str> {
    match message_type {
        RESERVES_ADD_OUTPUT | RESERVES_REMOVE_OUTPUT | RESERVES_INCREASE |
        RESERVES_DECREASE | RESERVES_UPDATE_OUTPUT => Some("reserves"),

        COLLATERAL_INCREASE | COLLATERAL_DECREASE | COLLATERAL_STATUS |
        COLLATERAL_ATTESTATION | COLLATERAL_ADD_PARTNER | COLLATERAL_REMOVE_PARTNER |
        COLLATERAL_CONSENT_REQUEST | COLLATERAL_CONSENT_RESPONSE => Some("collateral"),

        DEPOSIT_OPEN | DEPOSIT_CLOSE | DEPOSIT_UPDATE |
        DEPOSIT_LOCK_TRANSFER | DEPOSIT_FAIL_TRANSFER | DEPOSIT_FULFILL_TRANSFER => Some("deposit"),

        LEDGER_CLOSE | CHANNEL_CLOSE_TOMBSTONE => Some("lifecycle"),

        MAINTENANCE_FEE_COLLECT => Some("maintenance"),

        RECEIVING_COSIGN_INVOICE | RECEIVING_CREDIT_PAYMENT | UNCREDITED_PAYMENT => Some("receiving"),

        SENDING_LOCK_PAYMENT | SENDING_FAIL_PAYMENT | SENDING_FULFILL_PAYMENT => Some("sending"),

        SIGNED_UPDATE | SYNC_REQUEST | LEDGER_OPEN_REQUEST | LEDGER_OPEN_RESPONSE | ACK => Some("control"),

        QUORUM_JOIN_REQUEST | QUORUM_JOIN_RESPONSE | QUORUM_STATE_SYNC |
        QUORUM_VOTE_REQUEST | QUORUM_VOTE | QUORUM_MEMBERSHIP_CHANGE => Some("quorum"),

        RECOVERY_VOTE | RECOVERY_CLAIM_REQUEST | RECOVERY_CLAIM_SIGNATURE |
        RECOVERY_CLAIM_COMPLETE => Some("recovery"),

        RELAY_NWC_REQUEST | RELAY_NWC_RESPONSE | RELAY_NWC_DELIVERY_PROOF => Some("relay"),

        // V2 types
        LEDGER_UPDATE | LEDGER_UPDATE_RESPONSE => Some("ledger"),
        HANDSHAKE | HANDSHAKE_RESPONSE => Some("handshake"),
        SYNC | SYNC_RESPONSE => Some("sync"),
        RECOVERY | RECOVERY_RESPONSE => Some("recovery"),
        COORDINATION | COORDINATION_RESPONSE => Some("coordination"),
        RELAY | RELAY_RESPONSE => Some("relay"),

        _ => None,
    }
}

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
