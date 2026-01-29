// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wire Protocol Message Structs
//!
//! This module re-exports message structs from deposits-core for wire protocol
//! serialization. The `DepositsMessage` enum in `handler/messages.rs` implements
//! LDK's `Readable`/`Writeable` traits directly.
//!
//! ## Usage
//!
//! Use the core types directly:
//! ```ignore
//! use deposits_ldk::wire::ReservesIncreaseMsg;
//! let msg = ReservesIncreaseMsg { reserves_id: pk, new_amount: 100_000 };
//! ```

// ============================================================================
// Re-exports from deposits-core (canonical struct definitions)
// ============================================================================

pub use deposits_core::{
    // Reserves messages
    ReservesIncreaseMsg, ReservesDecreaseMsg, ReservesAddOutputMsg,
    ReservesRemoveOutputMsg, ReservesUpdateOutputMsg,
    UpdateReservesMsg, AcceptReservesMsg,
    // Deposit messages
    DepositOpenMsg, DepositCloseMsg, DepositUpdateMsg,
    // Collateral messages
    CollateralIncreaseMsg, CollateralDecreaseMsg,
    CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
    CollateralAttestationMsg,
    CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    // Fee and lifecycle messages
    FeeCollectMsg, LedgerCloseMsg,
    // Payment messages
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg,
    SendingFailPaymentMsg, SendingFulfillPaymentMsg,
    ReceivingCosignInvoiceMsg, UncreditedPaymentMsg,
    // Transfer messages
    DepositLockTransferMsg, DepositFailTransferMsg, DepositFulfillTransferMsg,
    // Sync messages
    SyncRequestMsg, ChannelCloseTombstoneMsg,
    // Quorum messages (wire-specific versions with Wire suffix)
    QuorumJoinRequestMsgWire, QuorumJoinResponseMsgWire, QuorumVoteMsgWire,
    QuorumMembershipChangeMsg, QuorumStateSyncMsg, QuorumVoteRequestMsg,
    // Recovery messages
    RecoveryVoteMsg, RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg, RecoveryClaimCompleteMsg,
    // Relay messages
    RelayNwcRequestMsg, RelayNwcResponseMsg, RelayNwcDeliveryProofMsg,
};

// ============================================================================
// Type aliases for backwards compatibility
// ============================================================================

/// Type alias for MaintenanceFeeCollect (legacy name)
pub type MaintenanceFeeCollectMsg = FeeCollectMsg;

/// Type alias for QuorumJoinRequestMsg (non-wire version is in types.rs)
pub type QuorumJoinRequestMsg = QuorumJoinRequestMsgWire;

/// Type alias for QuorumJoinResponseMsg (non-wire version is in types.rs)
pub type QuorumJoinResponseMsg = QuorumJoinResponseMsgWire;

/// Type alias for QuorumVoteMsg (non-wire version is in types.rs)
pub type QuorumVoteMsg = QuorumVoteMsgWire;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_core_types_reexported() {
        // Test that core types are accessible through re-exports
        let msg = ReservesIncreaseMsg {
            reserves_id: test_pubkey(),
            new_amount: 100_000,
        };
        assert_eq!(msg.new_amount, 100_000);
    }
}
