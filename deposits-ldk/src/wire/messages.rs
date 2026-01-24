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
//! - **LDK-only types** (defined here): Additional message types specific to
//!   LDK integration that are not needed in deposits-core
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

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

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
    // Fee and lifecycle messages
    FeeCollectMsg, LedgerCloseMsg,
    // Payment messages
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg,
    SendingFailPaymentMsg, SendingFulfillPaymentMsg,
    ReceivingCosignInvoiceMsg,
};

// ============================================================================
// Re-exports from adapters.rs (LDK Readable/Writeable wrappers)
// ============================================================================

pub use super::adapters::{
    LdkReservesIncreaseMsg, LdkReservesDecreaseMsg, LdkReservesAddOutputMsg,
    LdkReservesRemoveOutputMsg, LdkReservesUpdateOutputMsg,
    LdkUpdateReservesMsg, LdkAcceptReservesMsg,
    LdkDepositOpenMsg, LdkDepositCloseMsg, LdkDepositUpdateMsg,
    LdkCollateralIncreaseMsg, LdkCollateralDecreaseMsg,
    LdkFeeCollectMsg, LdkLedgerCloseMsg,
    LdkReceivingCreditPaymentMsg, LdkSendingLockPaymentMsg,
    LdkSendingFailPaymentMsg, LdkSendingFulfillPaymentMsg,
    LdkReceivingCosignInvoiceMsg,
};

// ============================================================================
// Type alias for backwards compatibility
// ============================================================================

/// Type alias for MaintenanceFeeCollect
pub type MaintenanceFeeCollectMsg = FeeCollectMsg;

// ============================================================================
// LDK-only Message Types (not in deposits-core)
// ============================================================================
//
// The following message types are specific to LDK integration and are not
// needed in the core protocol. They have native Readable/Writeable impls.

/// V1-compatible collateral add partner message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralAddPartnerMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub collateral_partner: PublicKey,
    pub collateral_partner_signature: [u8; 64],
}

impl Writeable for CollateralAddPartnerMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        self.collateral_partner.serialize().write(writer)?;
        writer.write_all(&self.collateral_partner_signature)?;
        Ok(())
    }
}

impl Readable for CollateralAddPartnerMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id =
            PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let cp_bytes: [u8; 33] = Readable::read(reader)?;
        let collateral_partner =
            PublicKey::from_slice(&cp_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut collateral_partner_signature = [0u8; 64];
        reader
            .read_exact(&mut collateral_partner_signature)
            .map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            operator_id,
            partner_id,
            collateral_partner,
            collateral_partner_signature,
        })
    }
}

/// V1-compatible collateral remove partner message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralRemovePartnerMsg {
    pub partner_id: PublicKey,
    pub collateral_partner: PublicKey,
    pub operator_signature: [u8; 64],
}

impl Writeable for CollateralRemovePartnerMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.partner_id.serialize().write(writer)?;
        self.collateral_partner.serialize().write(writer)?;
        writer.write_all(&self.operator_signature)?;
        Ok(())
    }
}

impl Readable for CollateralRemovePartnerMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let cp_bytes: [u8; 33] = Readable::read(reader)?;
        let collateral_partner =
            PublicKey::from_slice(&cp_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut operator_signature = [0u8; 64];
        reader
            .read_exact(&mut operator_signature)
            .map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            partner_id,
            collateral_partner,
            operator_signature,
        })
    }
}

// ============================================================================
// Transfer Messages
// ============================================================================

/// V1-compatible deposit lock transfer message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositLockTransferMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
    pub amount: u64,
    pub transfer_id: [u8; 32],
}

impl Writeable for DepositLockTransferMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.partner_id.serialize().write(writer)?;
        self.pubkey.serialize().write(writer)?;
        self.amount.write(writer)?;
        writer.write_all(&self.transfer_id)?;
        Ok(())
    }
}

impl Readable for DepositLockTransferMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let pk_bytes: [u8; 33] = Readable::read(reader)?;
        let pubkey = PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let amount: u64 = Readable::read(reader)?;
        let mut transfer_id = [0u8; 32];
        reader.read_exact(&mut transfer_id).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { partner_id, pubkey, amount, transfer_id })
    }
}

/// V1-compatible deposit fail transfer message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositFailTransferMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
    pub transfer_id: [u8; 32],
}

impl Writeable for DepositFailTransferMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.partner_id.serialize().write(writer)?;
        self.pubkey.serialize().write(writer)?;
        writer.write_all(&self.transfer_id)?;
        Ok(())
    }
}

impl Readable for DepositFailTransferMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let pk_bytes: [u8; 33] = Readable::read(reader)?;
        let pubkey = PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut transfer_id = [0u8; 32];
        reader.read_exact(&mut transfer_id).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { partner_id, pubkey, transfer_id })
    }
}

/// V1-compatible deposit fulfill transfer message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositFulfillTransferMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
    pub amount: u64,
    pub transfer_id: [u8; 32],
}

impl Writeable for DepositFulfillTransferMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.partner_id.serialize().write(writer)?;
        self.pubkey.serialize().write(writer)?;
        self.amount.write(writer)?;
        writer.write_all(&self.transfer_id)?;
        Ok(())
    }
}

impl Readable for DepositFulfillTransferMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let pk_bytes: [u8; 33] = Readable::read(reader)?;
        let pubkey = PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let amount: u64 = Readable::read(reader)?;
        let mut transfer_id = [0u8; 32];
        reader.read_exact(&mut transfer_id).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { partner_id, pubkey, amount, transfer_id })
    }
}

// ============================================================================
// Sync Messages
// ============================================================================

/// V1-compatible sync request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncRequestMsg {
    pub partner_id: PublicKey,
    pub operator_id: PublicKey,
    pub last_known_sequence: u64,
}

impl Writeable for SyncRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.partner_id.serialize().write(writer)?;
        self.operator_id.serialize().write(writer)?;
        self.last_known_sequence.write(writer)?;
        Ok(())
    }
}

impl Readable for SyncRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let last_known_sequence: u64 = Readable::read(reader)?;
        Ok(Self { partner_id, operator_id, last_known_sequence })
    }
}

// ============================================================================
// Channel Close Messages
// ============================================================================

/// V1-compatible channel close tombstone message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCloseTombstoneMsg {
    pub operator_pubkey: PublicKey,
    pub partner_pubkey: PublicKey,
    pub timestamp: u64,
    pub channel_id: [u8; 32],
    pub close_reason: Option<String>,
    pub sequence_number: u64,
}

impl Writeable for ChannelCloseTombstoneMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_pubkey.serialize().write(writer)?;
        self.partner_pubkey.serialize().write(writer)?;
        self.timestamp.write(writer)?;
        writer.write_all(&self.channel_id)?;
        if let Some(ref reason) = self.close_reason {
            1u8.write(writer)?;
            (reason.len() as u16).write(writer)?;
            writer.write_all(reason.as_bytes())?;
        } else {
            0u8.write(writer)?;
        }
        self.sequence_number.write(writer)?;
        Ok(())
    }
}

impl Readable for ChannelCloseTombstoneMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_pubkey = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_pubkey = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let timestamp: u64 = Readable::read(reader)?;
        let mut channel_id = [0u8; 32];
        reader.read_exact(&mut channel_id).map_err(|_| DecodeError::ShortRead)?;
        let has_reason: u8 = Readable::read(reader)?;
        let close_reason = if has_reason != 0 {
            let len: u16 = Readable::read(reader)?;
            let mut bytes = vec![0u8; len as usize];
            reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
            Some(String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?)
        } else {
            None
        };
        let sequence_number: u64 = Readable::read(reader)?;
        Ok(Self { operator_pubkey, partner_pubkey, timestamp, channel_id, close_reason, sequence_number })
    }
}

// ============================================================================
// Quorum Messages
// ============================================================================

/// V1-compatible quorum join request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinRequestMsg {
    pub requester_pubkey: PublicKey,
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub protocol_version: u16,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl Writeable for QuorumJoinRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.requester_pubkey.serialize().write(writer)?;
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        self.protocol_version.write(writer)?;
        self.timestamp.write(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

impl Readable for QuorumJoinRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let req_bytes: [u8; 33] = Readable::read(reader)?;
        let requester_pubkey = PublicKey::from_slice(&req_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let protocol_version: u16 = Readable::read(reader)?;
        let timestamp: u64 = Readable::read(reader)?;
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { requester_pubkey, operator_id, partner_id, protocol_version, timestamp, signature })
    }
}

/// V1-compatible quorum join response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinResponseMsg {
    pub accepted: bool,
    pub members: Vec<PublicKey>,
    pub threshold: u16,
    pub last_sequence: u64,
    pub current_state_hash: [u8; 32],
    pub rejection_reason: Option<String>,
}

impl Writeable for QuorumJoinResponseMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        (self.accepted as u8).write(writer)?;
        (self.members.len() as u16).write(writer)?;
        for pk in &self.members {
            pk.serialize().write(writer)?;
        }
        self.threshold.write(writer)?;
        self.last_sequence.write(writer)?;
        writer.write_all(&self.current_state_hash)?;
        if let Some(ref reason) = self.rejection_reason {
            1u8.write(writer)?;
            (reason.len() as u16).write(writer)?;
            writer.write_all(reason.as_bytes())?;
        } else {
            0u8.write(writer)?;
        }
        Ok(())
    }
}

impl Readable for QuorumJoinResponseMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let accepted_byte: u8 = Readable::read(reader)?;
        let accepted = accepted_byte != 0;
        let count: u16 = Readable::read(reader)?;
        let mut members = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let pk_bytes: [u8; 33] = Readable::read(reader)?;
            let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?;
            members.push(pk);
        }
        let threshold: u16 = Readable::read(reader)?;
        let last_sequence: u64 = Readable::read(reader)?;
        let mut current_state_hash = [0u8; 32];
        reader.read_exact(&mut current_state_hash).map_err(|_| DecodeError::ShortRead)?;
        let has_reason: u8 = Readable::read(reader)?;
        let rejection_reason = if has_reason != 0 {
            let len: u16 = Readable::read(reader)?;
            let mut bytes = vec![0u8; len as usize];
            reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
            Some(String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?)
        } else {
            None
        };
        Ok(Self { accepted, members, threshold, last_sequence, current_state_hash, rejection_reason })
    }
}

/// V1-compatible quorum membership change message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMembershipChangeMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub change_type: String,
    pub member_pubkey: PublicKey,
    pub new_members: Vec<PublicKey>,
}

impl Writeable for QuorumMembershipChangeMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        (self.change_type.len() as u16).write(writer)?;
        writer.write_all(self.change_type.as_bytes())?;
        self.member_pubkey.serialize().write(writer)?;
        (self.new_members.len() as u16).write(writer)?;
        for pk in &self.new_members {
            pk.serialize().write(writer)?;
        }
        Ok(())
    }
}

impl Readable for QuorumMembershipChangeMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        let change_type = String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?;
        let member_bytes: [u8; 33] = Readable::read(reader)?;
        let member_pubkey = PublicKey::from_slice(&member_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let count: u16 = Readable::read(reader)?;
        let mut new_members = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let pk_bytes: [u8; 33] = Readable::read(reader)?;
            let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?;
            new_members.push(pk);
        }
        Ok(Self { operator_id, partner_id, change_type, member_pubkey, new_members })
    }
}

// ============================================================================
// Recovery Messages
// ============================================================================

/// V1-compatible recovery vote message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryVoteMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub voter: PublicKey,
    pub is_conforming: bool,
    pub validated_hash: [u8; 32],
    pub validated_sequence: u64,
    pub substitute_nomination: Option<PublicKey>,
    pub discovered_violation: bool,
    pub signature: [u8; 64],
}

impl Writeable for RecoveryVoteMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.partner.serialize().write(writer)?;
        self.voter.serialize().write(writer)?;
        (self.is_conforming as u8).write(writer)?;
        writer.write_all(&self.validated_hash)?;
        self.validated_sequence.write(writer)?;
        if let Some(ref pk) = self.substitute_nomination {
            1u8.write(writer)?;
            pk.serialize().write(writer)?;
        } else {
            0u8.write(writer)?;
        }
        (self.discovered_violation as u8).write(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

impl Readable for RecoveryVoteMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let voter_bytes: [u8; 33] = Readable::read(reader)?;
        let voter = PublicKey::from_slice(&voter_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let is_conforming_byte: u8 = Readable::read(reader)?;
        let is_conforming = is_conforming_byte != 0;
        let mut validated_hash = [0u8; 32];
        reader.read_exact(&mut validated_hash).map_err(|_| DecodeError::ShortRead)?;
        let validated_sequence: u64 = Readable::read(reader)?;
        let has_sub: u8 = Readable::read(reader)?;
        let substitute_nomination = if has_sub != 0 {
            let pk_bytes: [u8; 33] = Readable::read(reader)?;
            Some(PublicKey::from_slice(&pk_bytes).map_err(|_| DecodeError::InvalidValue)?)
        } else {
            None
        };
        let violation_byte: u8 = Readable::read(reader)?;
        let discovered_violation = violation_byte != 0;
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { operator, partner, voter, is_conforming, validated_hash, validated_sequence, substitute_nomination, discovered_violation, signature })
    }
}

/// V1-compatible recovery claim request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimRequestMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub claimant: PublicKey,
    pub tier_index: u8,
    pub unsigned_tx: Vec<u8>,
    pub sighash: [u8; 32],
    pub destination_script: Vec<u8>,
    pub block_height: u32,
}

impl Writeable for RecoveryClaimRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.partner.serialize().write(writer)?;
        self.claimant.serialize().write(writer)?;
        self.tier_index.write(writer)?;
        (self.unsigned_tx.len() as u32).write(writer)?;
        writer.write_all(&self.unsigned_tx)?;
        writer.write_all(&self.sighash)?;
        (self.destination_script.len() as u16).write(writer)?;
        writer.write_all(&self.destination_script)?;
        self.block_height.write(writer)?;
        Ok(())
    }
}

impl Readable for RecoveryClaimRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let claimant_bytes: [u8; 33] = Readable::read(reader)?;
        let claimant = PublicKey::from_slice(&claimant_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let tier_index: u8 = Readable::read(reader)?;
        let tx_len: u32 = Readable::read(reader)?;
        let mut unsigned_tx = vec![0u8; tx_len as usize];
        reader.read_exact(&mut unsigned_tx).map_err(|_| DecodeError::ShortRead)?;
        let mut sighash = [0u8; 32];
        reader.read_exact(&mut sighash).map_err(|_| DecodeError::ShortRead)?;
        let script_len: u16 = Readable::read(reader)?;
        let mut destination_script = vec![0u8; script_len as usize];
        reader.read_exact(&mut destination_script).map_err(|_| DecodeError::ShortRead)?;
        let block_height: u32 = Readable::read(reader)?;
        Ok(Self { operator, partner, claimant, tier_index, unsigned_tx, sighash, destination_script, block_height })
    }
}

/// V1-compatible recovery claim signature message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimSignatureMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub signer: PublicKey,
    pub sighash: [u8; 32],
    pub signature: [u8; 64],
}

impl Writeable for RecoveryClaimSignatureMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.partner.serialize().write(writer)?;
        self.signer.serialize().write(writer)?;
        writer.write_all(&self.sighash)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

impl Readable for RecoveryClaimSignatureMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let signer_bytes: [u8; 33] = Readable::read(reader)?;
        let signer = PublicKey::from_slice(&signer_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut sighash = [0u8; 32];
        reader.read_exact(&mut sighash).map_err(|_| DecodeError::ShortRead)?;
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { operator, partner, signer, sighash, signature })
    }
}

/// V1-compatible recovery claim complete message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimCompleteMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub new_operator: PublicKey,
    pub claim_txid: [u8; 32],
    pub confirmation_block: u32,
    pub reason_code: u8,
}

impl Writeable for RecoveryClaimCompleteMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.partner.serialize().write(writer)?;
        self.new_operator.serialize().write(writer)?;
        writer.write_all(&self.claim_txid)?;
        self.confirmation_block.write(writer)?;
        self.reason_code.write(writer)?;
        Ok(())
    }
}

impl Readable for RecoveryClaimCompleteMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let op_bytes: [u8; 33] = Readable::read(reader)?;
        let operator = PublicKey::from_slice(&op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner = PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let new_op_bytes: [u8; 33] = Readable::read(reader)?;
        let new_operator = PublicKey::from_slice(&new_op_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut claim_txid = [0u8; 32];
        reader.read_exact(&mut claim_txid).map_err(|_| DecodeError::ShortRead)?;
        let confirmation_block: u32 = Readable::read(reader)?;
        let reason_code: u8 = Readable::read(reader)?;
        Ok(Self { operator, partner, new_operator, claim_txid, confirmation_block, reason_code })
    }
}

// ============================================================================
// Relay Messages
// ============================================================================

/// V1-compatible relay NWC request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNwcRequestMsg {
    pub request_id: [u8; 32],
    pub encrypted_content: Vec<u8>,
}

impl Writeable for RelayNwcRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        writer.write_all(&self.request_id)?;
        (self.encrypted_content.len() as u32).write(writer)?;
        writer.write_all(&self.encrypted_content)?;
        Ok(())
    }
}

impl Readable for RelayNwcRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut request_id = [0u8; 32];
        reader.read_exact(&mut request_id).map_err(|_| DecodeError::ShortRead)?;
        let len: u32 = Readable::read(reader)?;
        let mut encrypted_content = vec![0u8; len as usize];
        reader.read_exact(&mut encrypted_content).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { request_id, encrypted_content })
    }
}

/// V1-compatible relay NWC response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNwcResponseMsg {
    pub request_id: [u8; 32],
    pub encrypted_content: Vec<u8>,
}

impl Writeable for RelayNwcResponseMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        writer.write_all(&self.request_id)?;
        (self.encrypted_content.len() as u32).write(writer)?;
        writer.write_all(&self.encrypted_content)?;
        Ok(())
    }
}

impl Readable for RelayNwcResponseMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut request_id = [0u8; 32];
        reader.read_exact(&mut request_id).map_err(|_| DecodeError::ShortRead)?;
        let len: u32 = Readable::read(reader)?;
        let mut encrypted_content = vec![0u8; len as usize];
        reader.read_exact(&mut encrypted_content).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { request_id, encrypted_content })
    }
}

/// V1-compatible relay NWC delivery proof message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNwcDeliveryProofMsg {
    pub request_id: [u8; 32],
    pub proof: Vec<u8>,
}

impl Writeable for RelayNwcDeliveryProofMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        writer.write_all(&self.request_id)?;
        (self.proof.len() as u32).write(writer)?;
        writer.write_all(&self.proof)?;
        Ok(())
    }
}

impl Readable for RelayNwcDeliveryProofMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut request_id = [0u8; 32];
        reader.read_exact(&mut request_id).map_err(|_| DecodeError::ShortRead)?;
        let len: u32 = Readable::read(reader)?;
        let mut proof = vec![0u8; len as usize];
        reader.read_exact(&mut proof).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self { request_id, proof })
    }
}

// ============================================================================
// Collateral Attestation/Consent Messages
// ============================================================================

/// V1-compatible collateral attestation message
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollateralAttestationMsg {
    #[serde(with = "deposits_core::serde_pubkey")]
    pub operator: PublicKey,
    #[serde(with = "deposits_core::serde_pubkey")]
    pub collateral_partner: PublicKey,
    pub amount: u64,
    pub block_height: u32,
    #[serde(with = "deposits_core::serde_64")]
    pub signature: [u8; 64],
    #[serde(with = "deposits_core::serde_32")]
    pub ledger_hash: [u8; 32],
}

impl CollateralAttestationMsg {
    /// Get the available collateral amount
    pub fn available_collateral(&self) -> u64 {
        self.amount
    }
}

impl Writeable for CollateralAttestationMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.collateral_partner.serialize().write(writer)?;
        self.amount.write(writer)?;
        self.block_height.write(writer)?;
        writer.write_all(&self.signature)?;
        writer.write_all(&self.ledger_hash)?;
        Ok(())
    }
}

impl Readable for CollateralAttestationMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let collateral_partner =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let amount: u64 = Readable::read(reader)?;
        let block_height: u32 = Readable::read(reader)?;
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        let mut ledger_hash = [0u8; 32];
        reader.read_exact(&mut ledger_hash).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            operator,
            collateral_partner,
            amount,
            block_height,
            signature,
            ledger_hash,
        })
    }
}

/// V1-compatible collateral status message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralStatusMsg {
    pub collateral_operator: PublicKey,
    pub amount: u64,
    pub block_height: u32,
    pub signature: [u8; 64],
}

impl Writeable for CollateralStatusMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.collateral_operator.serialize().write(writer)?;
        self.amount.write(writer)?;
        self.block_height.write(writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}

impl Readable for CollateralStatusMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let collateral_operator =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let amount: u64 = Readable::read(reader)?;
        let block_height: u32 = Readable::read(reader)?;
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            collateral_operator,
            amount,
            block_height,
            signature,
        })
    }
}

/// V1-compatible collateral consent request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentRequestMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub operator_signature: [u8; 64],
}

impl Writeable for CollateralConsentRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        writer.write_all(&self.operator_signature)?;
        Ok(())
    }
}

impl Readable for CollateralConsentRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut operator_signature = [0u8; 64];
        reader.read_exact(&mut operator_signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            operator_id,
            partner_id,
            operator_signature,
        })
    }
}

/// V1-compatible collateral consent response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentResponseMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub consent_granted: bool,
    pub collateral_partner_signature: [u8; 64],
}

impl Writeable for CollateralConsentResponseMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        (self.consent_granted as u8).write(writer)?;
        writer.write_all(&self.collateral_partner_signature)?;
        Ok(())
    }
}

impl Readable for CollateralConsentResponseMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let consent_byte: u8 = Readable::read(reader)?;
        let consent_granted = consent_byte != 0;
        let mut collateral_partner_signature = [0u8; 64];
        reader.read_exact(&mut collateral_partner_signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            operator_id,
            partner_id,
            consent_granted,
            collateral_partner_signature,
        })
    }
}

// ============================================================================
// Additional Quorum Messages
// ============================================================================

/// V1-compatible quorum state sync message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumStateSyncMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub updates: Vec<Vec<u8>>,
    pub start_sequence: u64,
    pub is_final: bool,
}

impl Writeable for QuorumStateSyncMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        (self.updates.len() as u16).write(writer)?;
        for update in &self.updates {
            (update.len() as u32).write(writer)?;
            writer.write_all(update)?;
        }
        self.start_sequence.write(writer)?;
        (self.is_final as u8).write(writer)?;
        Ok(())
    }
}

impl Readable for QuorumStateSyncMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let count: u16 = Readable::read(reader)?;
        let mut updates = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let len: u32 = Readable::read(reader)?;
            let mut update = vec![0u8; len as usize];
            reader.read_exact(&mut update).map_err(|_| DecodeError::ShortRead)?;
            updates.push(update);
        }
        let start_sequence: u64 = Readable::read(reader)?;
        let is_final_byte: u8 = Readable::read(reader)?;
        let is_final = is_final_byte != 0;
        Ok(Self {
            operator_id,
            partner_id,
            updates,
            start_sequence,
            is_final,
        })
    }
}

/// V1-compatible quorum vote request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteRequestMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub vote_round_id: [u8; 32],
    pub sequence_number: u64,
    pub state_hash: [u8; 32],
    pub claimed_reserves: u64,
    pub collateral_amounts: Vec<u64>,
    pub reserves_outpoint: Vec<u8>,
    pub destination_script: Vec<u8>,
    pub fee_rate_sat_vbyte: u64,
}

impl Writeable for QuorumVoteRequestMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator_id.serialize().write(writer)?;
        self.partner_id.serialize().write(writer)?;
        writer.write_all(&self.vote_round_id)?;
        self.sequence_number.write(writer)?;
        writer.write_all(&self.state_hash)?;
        self.claimed_reserves.write(writer)?;
        (self.collateral_amounts.len() as u16).write(writer)?;
        for amount in &self.collateral_amounts {
            amount.write(writer)?;
        }
        (self.reserves_outpoint.len() as u16).write(writer)?;
        writer.write_all(&self.reserves_outpoint)?;
        (self.destination_script.len() as u16).write(writer)?;
        writer.write_all(&self.destination_script)?;
        self.fee_rate_sat_vbyte.write(writer)?;
        Ok(())
    }
}

impl Readable for QuorumVoteRequestMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator_id =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner_id =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut vote_round_id = [0u8; 32];
        reader.read_exact(&mut vote_round_id).map_err(|_| DecodeError::ShortRead)?;
        let sequence_number: u64 = Readable::read(reader)?;
        let mut state_hash = [0u8; 32];
        reader.read_exact(&mut state_hash).map_err(|_| DecodeError::ShortRead)?;
        let claimed_reserves: u64 = Readable::read(reader)?;
        let coll_count: u16 = Readable::read(reader)?;
        let mut collateral_amounts = Vec::with_capacity(coll_count as usize);
        for _ in 0..coll_count {
            collateral_amounts.push(Readable::read(reader)?);
        }
        let outpoint_len: u16 = Readable::read(reader)?;
        let mut reserves_outpoint = vec![0u8; outpoint_len as usize];
        reader.read_exact(&mut reserves_outpoint).map_err(|_| DecodeError::ShortRead)?;
        let script_len: u16 = Readable::read(reader)?;
        let mut destination_script = vec![0u8; script_len as usize];
        reader.read_exact(&mut destination_script).map_err(|_| DecodeError::ShortRead)?;
        let fee_rate_sat_vbyte: u64 = Readable::read(reader)?;
        Ok(Self {
            operator_id,
            partner_id,
            vote_round_id,
            sequence_number,
            state_hash,
            claimed_reserves,
            collateral_amounts,
            reserves_outpoint,
            destination_script,
            fee_rate_sat_vbyte,
        })
    }
}

/// V1-compatible quorum vote message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteMsg {
    pub vote_round_id: [u8; 32],
    pub voter_pubkey: PublicKey,
    pub vote: bool,
    pub voter_sequence: u64,
    pub voter_state_hash: [u8; 32],
    pub evidence: Option<Vec<u8>>,
    pub signature: [u8; 64],
    pub spend_signature: Option<[u8; 64]>,
}

impl Writeable for QuorumVoteMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        writer.write_all(&self.vote_round_id)?;
        self.voter_pubkey.serialize().write(writer)?;
        (self.vote as u8).write(writer)?;
        self.voter_sequence.write(writer)?;
        writer.write_all(&self.voter_state_hash)?;
        // Write evidence as optional
        match &self.evidence {
            Some(ev) => {
                1u8.write(writer)?;
                (ev.len() as u32).write(writer)?;
                writer.write_all(ev)?;
            }
            None => {
                0u8.write(writer)?;
            }
        }
        writer.write_all(&self.signature)?;
        // Write spend_signature as optional
        match &self.spend_signature {
            Some(sig) => {
                1u8.write(writer)?;
                writer.write_all(sig)?;
            }
            None => {
                0u8.write(writer)?;
            }
        }
        Ok(())
    }
}

impl Readable for QuorumVoteMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut vote_round_id = [0u8; 32];
        reader.read_exact(&mut vote_round_id).map_err(|_| DecodeError::ShortRead)?;
        let voter_bytes: [u8; 33] = Readable::read(reader)?;
        let voter_pubkey =
            PublicKey::from_slice(&voter_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let vote_byte: u8 = Readable::read(reader)?;
        let vote = vote_byte != 0;
        let voter_sequence: u64 = Readable::read(reader)?;
        let mut voter_state_hash = [0u8; 32];
        reader.read_exact(&mut voter_state_hash).map_err(|_| DecodeError::ShortRead)?;
        // Read optional evidence
        let has_evidence: u8 = Readable::read(reader)?;
        let evidence = if has_evidence != 0 {
            let len: u32 = Readable::read(reader)?;
            let mut ev = vec![0u8; len as usize];
            reader.read_exact(&mut ev).map_err(|_| DecodeError::ShortRead)?;
            Some(ev)
        } else {
            None
        };
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature).map_err(|_| DecodeError::ShortRead)?;
        // Read optional spend_signature
        let has_spend_sig: u8 = Readable::read(reader)?;
        let spend_signature = if has_spend_sig != 0 {
            let mut sig = [0u8; 64];
            reader.read_exact(&mut sig).map_err(|_| DecodeError::ShortRead)?;
            Some(sig)
        } else {
            None
        };
        Ok(Self {
            vote_round_id,
            voter_pubkey,
            vote,
            voter_sequence,
            voter_state_hash,
            evidence,
            signature,
            spend_signature,
        })
    }
}

// ============================================================================
// Additional Payment Messages
// ============================================================================

/// V1-compatible uncredited payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncreditedPaymentMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub payment_hash: [u8; 32],
    pub preimage: [u8; 32],
    pub deposit_pubkey: PublicKey,
    pub amount_msat: u64,
    pub invoice_cosignature: [u8; 64],
    pub settlement_sequence: u64,
    pub settlement_ledger_hash: [u8; 32],
    pub settlement_block_height: u32,
    pub accuser_signature: [u8; 64],
}

impl Writeable for UncreditedPaymentMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.operator.serialize().write(writer)?;
        self.partner.serialize().write(writer)?;
        writer.write_all(&self.payment_hash)?;
        writer.write_all(&self.preimage)?;
        self.deposit_pubkey.serialize().write(writer)?;
        self.amount_msat.write(writer)?;
        writer.write_all(&self.invoice_cosignature)?;
        self.settlement_sequence.write(writer)?;
        writer.write_all(&self.settlement_ledger_hash)?;
        self.settlement_block_height.write(writer)?;
        writer.write_all(&self.accuser_signature)?;
        Ok(())
    }
}

impl Readable for UncreditedPaymentMsg {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_bytes: [u8; 33] = Readable::read(reader)?;
        let operator =
            PublicKey::from_slice(&operator_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let partner_bytes: [u8; 33] = Readable::read(reader)?;
        let partner =
            PublicKey::from_slice(&partner_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let mut payment_hash = [0u8; 32];
        reader.read_exact(&mut payment_hash).map_err(|_| DecodeError::ShortRead)?;
        let mut preimage = [0u8; 32];
        reader.read_exact(&mut preimage).map_err(|_| DecodeError::ShortRead)?;
        let deposit_bytes: [u8; 33] = Readable::read(reader)?;
        let deposit_pubkey =
            PublicKey::from_slice(&deposit_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let amount_msat: u64 = Readable::read(reader)?;
        let mut invoice_cosignature = [0u8; 64];
        reader.read_exact(&mut invoice_cosignature).map_err(|_| DecodeError::ShortRead)?;
        let settlement_sequence: u64 = Readable::read(reader)?;
        let mut settlement_ledger_hash = [0u8; 32];
        reader.read_exact(&mut settlement_ledger_hash).map_err(|_| DecodeError::ShortRead)?;
        let settlement_block_height: u32 = Readable::read(reader)?;
        let mut accuser_signature = [0u8; 64];
        reader.read_exact(&mut accuser_signature).map_err(|_| DecodeError::ShortRead)?;
        Ok(Self {
            operator,
            partner,
            payment_hash,
            preimage,
            deposit_pubkey,
            amount_msat,
            invoice_cosignature,
            settlement_sequence,
            settlement_ledger_hash,
            settlement_block_height,
            accuser_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey2() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_collateral_add_partner_roundtrip() {
        use lightning::util::ser::Writeable;

        let msg = CollateralAddPartnerMsg {
            operator_id: test_pubkey(),
            partner_id: test_pubkey2(),
            collateral_partner: test_pubkey(),
            collateral_partner_signature: [42u8; 64],
        };

        let encoded = msg.encode();
        let decoded: CollateralAddPartnerMsg =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_quorum_vote_roundtrip() {
        use lightning::util::ser::Writeable;

        let msg = QuorumVoteMsg {
            vote_round_id: [1u8; 32],
            voter_pubkey: test_pubkey(),
            vote: true,
            voter_sequence: 42,
            voter_state_hash: [2u8; 32],
            evidence: Some(vec![1, 2, 3, 4]),
            signature: [3u8; 64],
            spend_signature: Some([4u8; 64]),
        };

        let encoded = msg.encode();
        let decoded: QuorumVoteMsg =
            Readable::read(&mut lightning::io::Cursor::new(&encoded)).unwrap();

        assert_eq!(msg, decoded);
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
}
