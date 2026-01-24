// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! V1 Wire Protocol Message Structs
//!
//! This module contains message structs for the V1 wire protocol format.
//! These structs implement LDK's `Readable` and `Writeable` traits for
//! wire serialization.
//!
//! ## Architecture
//!
//! Message types are organized as follows:
//!
//! - **Core types** (from `deposits_core`): The canonical struct definitions
//!   with `WireEncode`/`WireDecode` implementations
//! - **LDK wrappers** (from `adapters.rs`): Newtype wrappers that implement
//!   LDK's `Readable`/`Writeable` traits
//!
//! ## Usage
//!
//! For struct construction and field access, use the core types directly:
//! ```ignore
//! use deposits_ldk::wire::ReservesIncreaseMsg;
//! let msg = ReservesIncreaseMsg { partner_id: pk, new_amount: 100_000 };
//! ```
//!
//! For LDK serialization, use the LdkXxxMsg wrappers:
//! ```ignore
//! use deposits_ldk::wire::LdkReservesIncreaseMsg;
//! use lightning::util::ser::{Readable, Writeable};
//! let ldk_msg = LdkReservesIncreaseMsg::from(msg);
//! let bytes = ldk_msg.encode();
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
    CollateralAttestationMsg, CollateralStatusMsg,
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
// Re-exports from adapters.rs (LDK Readable/Writeable wrappers)
// ============================================================================

pub use super::adapters::{
    // Reserves wrappers
    LdkReservesIncreaseMsg, LdkReservesDecreaseMsg, LdkReservesAddOutputMsg,
    LdkReservesRemoveOutputMsg, LdkReservesUpdateOutputMsg,
    LdkUpdateReservesMsg, LdkAcceptReservesMsg,
    // Deposit wrappers
    LdkDepositOpenMsg, LdkDepositCloseMsg, LdkDepositUpdateMsg,
    // Collateral wrappers
    LdkCollateralIncreaseMsg, LdkCollateralDecreaseMsg,
    LdkCollateralAddPartnerMsg, LdkCollateralRemovePartnerMsg,
    LdkCollateralAttestationMsg, LdkCollateralStatusMsg,
    LdkCollateralConsentRequestMsg, LdkCollateralConsentResponseMsg,
    // Fee and lifecycle wrappers
    LdkFeeCollectMsg, LdkLedgerCloseMsg,
    // Payment wrappers
    LdkReceivingCreditPaymentMsg, LdkSendingLockPaymentMsg,
    LdkSendingFailPaymentMsg, LdkSendingFulfillPaymentMsg,
    LdkReceivingCosignInvoiceMsg, LdkUncreditedPaymentMsg,
    // Transfer wrappers
    LdkDepositLockTransferMsg, LdkDepositFailTransferMsg, LdkDepositFulfillTransferMsg,
    // Sync wrappers
    LdkSyncRequestMsg, LdkChannelCloseTombstoneMsg,
    // Quorum wrappers
    LdkQuorumJoinRequestMsgWire, LdkQuorumJoinResponseMsgWire, LdkQuorumVoteMsgWire,
    LdkQuorumMembershipChangeMsg, LdkQuorumStateSyncMsg, LdkQuorumVoteRequestMsg,
    // Recovery wrappers
    LdkRecoveryVoteMsg, LdkRecoveryClaimRequestMsg, LdkRecoveryClaimSignatureMsg, LdkRecoveryClaimCompleteMsg,
    // Relay wrappers
    LdkRelayNwcRequestMsg, LdkRelayNwcResponseMsg, LdkRelayNwcDeliveryProofMsg,
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
    use lightning::util::ser::{Readable, Writeable};

    fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey2() -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_collateral_add_partner_roundtrip() {
        let msg = CollateralAddPartnerMsg {
            operator_id: test_pubkey(),
            partner_id: test_pubkey2(),
            collateral_partner: test_pubkey(),
            collateral_partner_signature: [42u8; 64],
        };

        let ldk_msg = LdkCollateralAddPartnerMsg::from(msg.clone());
        let encoded = ldk_msg.encode();
        let decoded: LdkCollateralAddPartnerMsg =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.0, msg);
    }

    #[test]
    fn test_quorum_vote_roundtrip() {
        let msg = QuorumVoteMsgWire {
            vote_round_id: [1u8; 32],
            voter_pubkey: test_pubkey(),
            vote: true,
            voter_sequence: 42,
            voter_state_hash: [2u8; 32],
            evidence: Some(vec![1, 2, 3, 4]),
            signature: [3u8; 64],
            spend_signature: Some([4u8; 64]),
        };

        let ldk_msg = LdkQuorumVoteMsgWire::from(msg.clone());
        let encoded = ldk_msg.encode();
        let decoded: LdkQuorumVoteMsgWire =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.0, msg);
    }

    #[test]
    fn test_core_types_reexported() {
        // Test that core types are accessible through re-exports
        let msg = ReservesIncreaseMsg {
            partner_id: test_pubkey(),
            new_amount: 100_000,
        };
        assert_eq!(msg.new_amount, 100_000);

        // Test LDK wrapper
        let ldk_msg = LdkReservesIncreaseMsg::from(msg.clone());
        assert_eq!(ldk_msg.0.new_amount, 100_000);
    }

    #[test]
    fn test_recovery_msg_roundtrip() {
        let msg = RecoveryVoteMsg {
            operator: test_pubkey(),
            partner: test_pubkey2(),
            voter: test_pubkey(),
            is_conforming: true,
            validated_hash: [5u8; 32],
            validated_sequence: 100,
            substitute_nomination: Some(test_pubkey2()),
            discovered_violation: false,
            signature: [6u8; 64],
        };

        let ldk_msg = LdkRecoveryVoteMsg::from(msg.clone());
        let encoded = ldk_msg.encode();
        let decoded: LdkRecoveryVoteMsg =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.0, msg);
    }

    #[test]
    fn test_relay_msg_roundtrip() {
        let msg = RelayNwcRequestMsg {
            request_id: [7u8; 32],
            encrypted_content: vec![1, 2, 3, 4, 5],
        };

        let ldk_msg = LdkRelayNwcRequestMsg::from(msg.clone());
        let encoded = ldk_msg.encode();
        let decoded: LdkRelayNwcRequestMsg =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.0, msg);
    }
}
