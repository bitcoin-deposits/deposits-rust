// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Wire Adapters for deposits-core Types
//!
//! This module provides newtype wrappers that implement LDK's `Readable`/`Writeable`
//! traits for deposits-core message types. This bridges the gap between deposits-core's
//! `WireEncode`/`WireDecode` traits and LDK's serialization system.
//!
//! ## Design
//!
//! Due to Rust's orphan rule, we cannot implement foreign traits (LDK's Readable/Writeable)
//! on foreign types (deposits-core's message types). The newtype pattern solves this by
//! creating wrapper types owned by this crate.
//!
//! Each wrapper:
//! - Contains the core type via `pub` field for easy access
//! - Implements `From`/`Into` for seamless conversion
//! - Delegates serialization to the underlying `WireEncode`/`WireDecode` implementations
//!
//! ## Usage
//!
//! ```ignore
//! use deposits_ldk::wire::adapters::LdkReservesIncreaseMsg;
//! use deposits_core::ReservesIncreaseMsg;
//! use lightning::util::ser::{Readable, Writeable};
//!
//! // Wrap a core type for LDK serialization
//! let core_msg = ReservesIncreaseMsg { partner_id: pk, new_amount: 100_000 };
//! let ldk_msg = LdkReservesIncreaseMsg(core_msg);
//!
//! // Serialize using LDK's Writeable
//! let bytes = ldk_msg.encode();
//!
//! // Deserialize using LDK's Readable
//! let decoded: LdkReservesIncreaseMsg = Readable::read(&mut &bytes[..])?;
//!
//! // Access the inner type
//! assert_eq!(decoded.0.new_amount, 100_000);
//! ```

use deposits_core::{WireEncode, WireDecode};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

/// Macro to create an LDK newtype wrapper for a deposits-core wire message type.
///
/// This macro generates a wrapper struct that:
/// - Wraps the core type with a public field
/// - Implements Readable by delegating to WireDecode
/// - Implements Writeable by delegating to WireEncode
/// - Implements From/Into for conversions
/// - Implements Clone, Debug, PartialEq, Eq
macro_rules! ldk_wire_wrapper {
    (
        $(#[$meta:meta])*
        $wrapper_name:ident => $core_type:ty
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $wrapper_name(pub $core_type);

        impl $wrapper_name {
            /// Create a new wrapper from the core type
            pub fn new(inner: $core_type) -> Self {
                Self(inner)
            }

            /// Get a reference to the inner type
            pub fn inner(&self) -> &$core_type {
                &self.0
            }

            /// Consume the wrapper and return the inner type
            pub fn into_inner(self) -> $core_type {
                self.0
            }
        }

        impl From<$core_type> for $wrapper_name {
            fn from(inner: $core_type) -> Self {
                Self(inner)
            }
        }

        impl From<$wrapper_name> for $core_type {
            fn from(wrapper: $wrapper_name) -> Self {
                wrapper.0
            }
        }

        impl Readable for $wrapper_name {
            fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
                // Create an adapter that implements std::io::Read
                let mut adapter = IoReadAdapter(reader);
                let inner = <$core_type as WireDecode>::wire_decode(&mut adapter)
                    .map_err(|_| DecodeError::InvalidValue)?;
                Ok(Self(inner))
            }
        }

        impl Writeable for $wrapper_name {
            fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
                // Create an adapter that implements std::io::Write
                let mut adapter = IoWriteAdapter(writer);
                self.0.wire_encode(&mut adapter)
                    .map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e.to_string()))
            }
        }
    };
}

/// Adapter to bridge `lightning::io::Read` to `std::io::Read`
///
/// LDK uses `bitcoin::io::Read` (re-exported as `lightning::io::Read`), while
/// deposits-core uses `std::io::Read`. This adapter bridges the two.
struct IoReadAdapter<'a, R: lightning::io::Read>(&'a mut R);

impl<'a, R: lightning::io::Read> std::io::Read for IoReadAdapter<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

/// Adapter to bridge `lightning::util::ser::Writer` to `std::io::Write`
///
/// LDK's `Writer` trait is similar to `std::io::Write` but not identical.
/// This adapter bridges the two.
struct IoWriteAdapter<'a, W: Writer>(&'a mut W);

impl<'a, W: Writer> std::io::Write for IoWriteAdapter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// Reserves Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReservesIncreaseMsg`
    LdkReservesIncreaseMsg => deposits_core::ReservesIncreaseMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReservesDecreaseMsg`
    LdkReservesDecreaseMsg => deposits_core::ReservesDecreaseMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReservesAddOutputMsg`
    LdkReservesAddOutputMsg => deposits_core::ReservesAddOutputMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReservesRemoveOutputMsg`
    LdkReservesRemoveOutputMsg => deposits_core::ReservesRemoveOutputMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReservesUpdateOutputMsg`
    LdkReservesUpdateOutputMsg => deposits_core::ReservesUpdateOutputMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::UpdateReservesMsg`
    LdkUpdateReservesMsg => deposits_core::UpdateReservesMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::AcceptReservesMsg`
    LdkAcceptReservesMsg => deposits_core::AcceptReservesMsg
}

// ============================================================================
// Deposit Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositOpenMsg`
    LdkDepositOpenMsg => deposits_core::DepositOpenMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositCloseMsg`
    LdkDepositCloseMsg => deposits_core::DepositCloseMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositUpdateMsg`
    LdkDepositUpdateMsg => deposits_core::DepositUpdateMsg
}

// ============================================================================
// Collateral Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralIncreaseMsg`
    LdkCollateralIncreaseMsg => deposits_core::CollateralIncreaseMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralDecreaseMsg`
    LdkCollateralDecreaseMsg => deposits_core::CollateralDecreaseMsg
}

// ============================================================================
// Fee and Ledger Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::FeeCollectMsg`
    LdkFeeCollectMsg => deposits_core::FeeCollectMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::LedgerCloseMsg`
    LdkLedgerCloseMsg => deposits_core::LedgerCloseMsg
}

// ============================================================================
// Payment Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReceivingCreditPaymentMsg`
    LdkReceivingCreditPaymentMsg => deposits_core::ReceivingCreditPaymentMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::SendingLockPaymentMsg`
    LdkSendingLockPaymentMsg => deposits_core::SendingLockPaymentMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::SendingFailPaymentMsg`
    LdkSendingFailPaymentMsg => deposits_core::SendingFailPaymentMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::SendingFulfillPaymentMsg`
    LdkSendingFulfillPaymentMsg => deposits_core::SendingFulfillPaymentMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ReceivingCosignInvoiceMsg`
    LdkReceivingCosignInvoiceMsg => deposits_core::ReceivingCosignInvoiceMsg
}

// ============================================================================
// Collateral Message Wrappers (additional)
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralAddPartnerMsg`
    LdkCollateralAddPartnerMsg => deposits_core::CollateralAddPartnerMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralRemovePartnerMsg`
    LdkCollateralRemovePartnerMsg => deposits_core::CollateralRemovePartnerMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralAttestationMsg`
    LdkCollateralAttestationMsg => deposits_core::CollateralAttestationMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralStatusMsg`
    LdkCollateralStatusMsg => deposits_core::CollateralStatusMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralConsentRequestMsg`
    LdkCollateralConsentRequestMsg => deposits_core::CollateralConsentRequestMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::CollateralConsentResponseMsg`
    LdkCollateralConsentResponseMsg => deposits_core::CollateralConsentResponseMsg
}

// ============================================================================
// Transfer Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositLockTransferMsg`
    LdkDepositLockTransferMsg => deposits_core::DepositLockTransferMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositFailTransferMsg`
    LdkDepositFailTransferMsg => deposits_core::DepositFailTransferMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::DepositFulfillTransferMsg`
    LdkDepositFulfillTransferMsg => deposits_core::DepositFulfillTransferMsg
}

// ============================================================================
// Sync Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::SyncRequestMsg`
    LdkSyncRequestMsg => deposits_core::SyncRequestMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::ChannelCloseTombstoneMsg`
    LdkChannelCloseTombstoneMsg => deposits_core::ChannelCloseTombstoneMsg
}

// ============================================================================
// Quorum Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumJoinRequestMsgWire`
    LdkQuorumJoinRequestMsgWire => deposits_core::QuorumJoinRequestMsgWire
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumJoinResponseMsgWire`
    LdkQuorumJoinResponseMsgWire => deposits_core::QuorumJoinResponseMsgWire
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumVoteMsgWire`
    LdkQuorumVoteMsgWire => deposits_core::QuorumVoteMsgWire
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumMembershipChangeMsg`
    LdkQuorumMembershipChangeMsg => deposits_core::QuorumMembershipChangeMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumStateSyncMsg`
    LdkQuorumStateSyncMsg => deposits_core::QuorumStateSyncMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::QuorumVoteRequestMsg`
    LdkQuorumVoteRequestMsg => deposits_core::QuorumVoteRequestMsg
}

// ============================================================================
// Recovery Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RecoveryVoteMsg`
    LdkRecoveryVoteMsg => deposits_core::RecoveryVoteMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RecoveryClaimRequestMsg`
    LdkRecoveryClaimRequestMsg => deposits_core::RecoveryClaimRequestMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RecoveryClaimSignatureMsg`
    LdkRecoveryClaimSignatureMsg => deposits_core::RecoveryClaimSignatureMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RecoveryClaimCompleteMsg`
    LdkRecoveryClaimCompleteMsg => deposits_core::RecoveryClaimCompleteMsg
}

// ============================================================================
// Relay Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RelayNwcRequestMsg`
    LdkRelayNwcRequestMsg => deposits_core::RelayNwcRequestMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RelayNwcResponseMsg`
    LdkRelayNwcResponseMsg => deposits_core::RelayNwcResponseMsg
}

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::RelayNwcDeliveryProofMsg`
    LdkRelayNwcDeliveryProofMsg => deposits_core::RelayNwcDeliveryProofMsg
}

// ============================================================================
// Other Message Wrappers
// ============================================================================

ldk_wire_wrapper! {
    /// LDK wrapper for `deposits_core::UncreditedPaymentMsg`
    LdkUncreditedPaymentMsg => deposits_core::UncreditedPaymentMsg
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

    fn test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_reserves_increase_roundtrip() {
        let core_msg = deposits_core::ReservesIncreaseMsg {
            partner_id: test_pubkey(1),
            new_amount: 100_000,
        };
        let ldk_msg = LdkReservesIncreaseMsg(core_msg.clone());

        // Encode using Writeable
        let encoded = ldk_msg.encode();

        // Decode using Readable
        let decoded: LdkReservesIncreaseMsg = Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.0, core_msg);
    }

    #[test]
    fn test_deposit_open_roundtrip() {
        let core_msg = deposits_core::DepositOpenMsg {
            partner_id: test_pubkey(1),
            pubkey: test_pubkey(2),
            fees: Some(deposits_core::FeeStructure {
                annualized_fixed: 1000,
                annualized_bps: 50,
                frequency_blocks: 144,
            }),
            payment_hash: Some([42u8; 32]),
            invoice: Some("lnbc1000n1ptest".to_string()),
            cosigner_guarantee_signature: None,
        };
        let ldk_msg = LdkDepositOpenMsg::from(core_msg.clone());

        // Encode using Writeable
        let encoded = ldk_msg.encode();

        // Decode using Readable
        let decoded: LdkDepositOpenMsg = Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(decoded.into_inner(), core_msg);
    }

    #[test]
    fn test_receiving_credit_payment_roundtrip() {
        let core_msg = deposits_core::ReceivingCreditPaymentMsg {
            payment_hash: [1u8; 32],
            deposit_pubkey: test_pubkey(2),
            amount: 50_000,
            invoice_id: "inv_123".to_string(),
            partner_id: test_pubkey(1),
            sequence_number: 42,
        };
        let ldk_msg = LdkReceivingCreditPaymentMsg::new(core_msg.clone());

        // Encode using Writeable
        let encoded = ldk_msg.encode();

        // Decode using Readable
        let decoded: LdkReceivingCreditPaymentMsg = Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(*decoded.inner(), core_msg);
    }

    #[test]
    fn test_conversions() {
        let core_msg = deposits_core::ReservesIncreaseMsg {
            partner_id: test_pubkey(1),
            new_amount: 50_000,
        };

        // Test From<Core> for Wrapper
        let wrapper: LdkReservesIncreaseMsg = core_msg.clone().into();
        assert_eq!(wrapper.0.new_amount, 50_000);

        // Test From<Wrapper> for Core
        let back: deposits_core::ReservesIncreaseMsg = wrapper.into();
        assert_eq!(back, core_msg);
    }
}
