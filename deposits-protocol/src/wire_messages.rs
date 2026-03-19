// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wire Protocol Message Structs
//!
//! This module contains message structs for wire protocol serialization.
//! These are pure data types with LDK-independent serialization.
//!
//! ## Design
//!
//! - Structs are plain data with no LDK dependencies
//! - Serialization uses std::io traits
//! - LDK Readable/Writeable impls are provided separately in deposits-ldk

use bitcoin::secp256k1::PublicKey;
use std::io::{self, Read, Write};

use crate::types::{FeeStructure, QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumVoteMsg};

// ============================================================================
// Wire Codec Traits
// ============================================================================

/// Error type for wire encoding/decoding
#[derive(Debug, Clone)]
pub enum WireError {
    /// IO error
    Io(String),
    /// Invalid data
    InvalidValue(String),
    /// Unexpected end of data
    ShortRead,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "IO error: {}", e),
            WireError::InvalidValue(e) => write!(f, "Invalid value: {}", e),
            WireError::ShortRead => write!(f, "Unexpected end of data"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e.to_string())
    }
}

/// Trait for encoding a message to wire format
pub trait WireEncode {
    /// Encode to a writer
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError>;

    /// Encode to bytes
    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.wire_encode(&mut bytes).expect("Vec write should never fail");
        bytes
    }
}

/// Trait for decoding a message from wire format
pub trait WireDecode: Sized {
    /// Decode from a reader
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError>;

    /// Decode from bytes
    fn from_wire_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut cursor = std::io::Cursor::new(bytes);
        Self::wire_decode(&mut cursor)
    }
}

// ============================================================================
// Helper functions for common encodings
// ============================================================================

fn write_pubkey<W: Write>(writer: &mut W, pk: &PublicKey) -> Result<(), WireError> {
    writer.write_all(&pk.serialize())?;
    Ok(())
}

fn read_pubkey<R: Read>(reader: &mut R) -> Result<PublicKey, WireError> {
    let mut bytes = [0u8; 33];
    reader.read_exact(&mut bytes)?;
    PublicKey::from_slice(&bytes)
        .map_err(|_| WireError::InvalidValue("Invalid public key".to_string()))
}

fn write_u8<W: Write>(writer: &mut W, val: u8) -> Result<(), WireError> {
    writer.write_all(&[val])?;
    Ok(())
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, WireError> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn write_u16<W: Write>(writer: &mut W, val: u16) -> Result<(), WireError> {
    writer.write_all(&val.to_be_bytes())?;
    Ok(())
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16, WireError> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn write_u32<W: Write>(writer: &mut W, val: u32) -> Result<(), WireError> {
    writer.write_all(&val.to_be_bytes())?;
    Ok(())
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, WireError> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn write_u64<W: Write>(writer: &mut W, val: u64) -> Result<(), WireError> {
    writer.write_all(&val.to_be_bytes())?;
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, WireError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn write_32<W: Write>(writer: &mut W, val: &[u8; 32]) -> Result<(), WireError> {
    writer.write_all(val)?;
    Ok(())
}

fn read_32<R: Read>(reader: &mut R) -> Result<[u8; 32], WireError> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_bytes32<W: Write>(writer: &mut W, bytes: &[u8; 32]) -> Result<(), WireError> {
    writer.write_all(bytes)?;
    Ok(())
}

fn read_bytes32<R: Read>(reader: &mut R) -> Result<[u8; 32], WireError> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_bytes64<W: Write>(writer: &mut W, bytes: &[u8; 64]) -> Result<(), WireError> {
    writer.write_all(bytes)?;
    Ok(())
}

fn read_bytes64<R: Read>(reader: &mut R) -> Result<[u8; 64], WireError> {
    let mut buf = [0u8; 64];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_string<W: Write>(writer: &mut W, s: &str) -> Result<(), WireError> {
    write_u16(writer, s.len() as u16)?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

fn read_string<R: Read>(reader: &mut R) -> Result<String, WireError> {
    let len = read_u16(reader)? as usize;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| WireError::InvalidValue("Invalid UTF-8 string".to_string()))
}

fn write_optional<W: Write, T, F>(writer: &mut W, opt: &Option<T>, write_fn: F) -> Result<(), WireError>
where
    F: FnOnce(&mut W, &T) -> Result<(), WireError>,
{
    if let Some(ref val) = opt {
        write_u8(writer, 1)?;
        write_fn(writer, val)?;
    } else {
        write_u8(writer, 0)?;
    }
    Ok(())
}

fn read_optional<R: Read, T, F>(reader: &mut R, read_fn: F) -> Result<Option<T>, WireError>
where
    F: FnOnce(&mut R) -> Result<T, WireError>,
{
    let has_value = read_u8(reader)?;
    if has_value != 0 {
        Ok(Some(read_fn(reader)?))
    } else {
        Ok(None)
    }
}

// ============================================================================
// FeeStructure Encoding
// ============================================================================

impl WireEncode for FeeStructure {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u64(writer, self.annualized_fixed)?;
        write_u16(writer, self.annualized_bps)?;
        write_u32(writer, self.frequency_blocks)?;
        Ok(())
    }
}

impl WireDecode for FeeStructure {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(FeeStructure {
            annualized_fixed: read_u64(reader)?,
            annualized_bps: read_u16(reader)?,
            frequency_blocks: read_u32(reader)?,
        })
    }
}

// ============================================================================
// WireEncode/WireDecode for types.rs Quorum types
// ============================================================================

impl WireEncode for QuorumJoinRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.requester_pubkey)?;
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_u16(writer, self.protocol_version)?;
        write_u64(writer, self.timestamp)?;
        write_bytes64(writer, &self.signature)?;
        Ok(())
    }
}

impl WireDecode for QuorumJoinRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            requester_pubkey: read_pubkey(reader)?,
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            protocol_version: read_u16(reader)?,
            timestamp: read_u64(reader)?,
            signature: read_bytes64(reader)?,
        })
    }
}

impl WireEncode for QuorumJoinResponseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u8(writer, self.accepted as u8)?;
        write_u16(writer, self.members.len() as u16)?;
        for pk in &self.members {
            write_pubkey(writer, pk)?;
        }
        write_u16(writer, self.threshold)?;
        write_u64(writer, self.last_sequence)?;
        write_bytes32(writer, &self.current_hash)?;
        write_optional(writer, &self.rejection_reason, |w, s| write_string(w, s))?;
        Ok(())
    }
}

impl WireDecode for QuorumJoinResponseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let accepted = read_u8(reader)? != 0;
        let count = read_u16(reader)? as usize;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(read_pubkey(reader)?);
        }
        Ok(Self {
            accepted,
            members,
            threshold: read_u16(reader)?,
            last_sequence: read_u64(reader)?,
            current_hash: read_bytes32(reader)?,
            rejection_reason: read_optional(reader, read_string)?,
        })
    }
}

impl WireEncode for QuorumVoteMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.vote_round_id)?;
        write_pubkey(writer, &self.voter_pubkey)?;
        write_u8(writer, self.vote as u8)?;
        write_u64(writer, self.voter_sequence)?;
        write_bytes32(writer, &self.voter_state_hash)?;
        // Write evidence as optional
        write_optional(writer, &self.evidence, |w, ev| {
            write_u32(w, ev.len() as u32)?;
            w.write_all(ev)?;
            Ok(())
        })?;
        write_bytes64(writer, &self.signature)?;
        // Write spend_signature as optional
        write_optional(writer, &self.spend_signature, |w, sig| write_bytes64(w, sig))?;
        Ok(())
    }
}

impl WireDecode for QuorumVoteMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let vote_round_id = read_bytes32(reader)?;
        let voter_pubkey = read_pubkey(reader)?;
        let vote = read_u8(reader)? != 0;
        let voter_sequence = read_u64(reader)?;
        let voter_state_hash = read_bytes32(reader)?;
        // Read optional evidence
        let evidence = read_optional(reader, |r| {
            let len = read_u32(r)? as usize;
            let mut ev = vec![0u8; len];
            r.read_exact(&mut ev)?;
            Ok(ev)
        })?;
        let signature = read_bytes64(reader)?;
        // Read optional spend_signature
        let spend_signature = read_optional(reader, read_bytes64)?;
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
// Reserves Messages
// ============================================================================

/// reserves add output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesAddOutputMsg {
    pub initial_amount: u64,
    pub spend_to: PublicKey,
    pub reserves_id: String,
    pub quorum_members: Vec<PublicKey>,
}

impl WireEncode for ReservesAddOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u64(writer, self.initial_amount)?;
        write_pubkey(writer, &self.spend_to)?;
        write_string(writer, &self.reserves_id)?;
        write_u16(writer, self.quorum_members.len() as u16)?;
        for pk in &self.quorum_members {
            write_pubkey(writer, pk)?;
        }
        Ok(())
    }
}

impl WireDecode for ReservesAddOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let initial_amount = read_u64(reader)?;
        let spend_to = read_pubkey(reader)?;
        let reserves_id = read_string(reader)?;
        let count = read_u16(reader)? as usize;
        let mut quorum_members = Vec::with_capacity(count);
        for _ in 0..count {
            quorum_members.push(read_pubkey(reader)?);
        }
        Ok(Self {
            initial_amount,
            spend_to,
            reserves_id,
            quorum_members,
        })
    }
}

/// reserves remove output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesRemoveOutputMsg {
    pub reserves_id: String,
    pub remove_all: bool,
}

impl WireEncode for ReservesRemoveOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_u8(writer, self.remove_all as u8)?;
        Ok(())
    }
}

impl WireDecode for ReservesRemoveOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            remove_all: read_u8(reader)? != 0,
        })
    }
}

/// reserves update output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesUpdateOutputMsg {
    pub reserves_id: String,
    pub spend_to: PublicKey,
}

impl WireEncode for ReservesUpdateOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.spend_to)?;
        Ok(())
    }
}

impl WireDecode for ReservesUpdateOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            spend_to: read_pubkey(reader)?,
        })
    }
}

// ============================================================================
// Reserves Commitment Protocol Messages
// ============================================================================

/// UpdateReserves message - sent to propose reserves commitment to counterparty
///
/// This custom message is sent after calling propose_extra_outputs() on the
/// ChannelManager to notify the counterparty of the proposed extra outputs.
/// The counterparty should respond with AcceptReserves after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
    /// Reserves amount in satoshis
    pub reserves_sats: u64,
    /// The script pubkey for the reserves output
    pub script_pubkey: Vec<u8>,
    /// Our ledger hash being committed
    pub ledger_hash: [u8; 32],
    /// Remote ledger hash for bidirectional verification
    pub remote_ledger_hash: [u8; 32],
}

impl WireEncode for UpdateReservesMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.channel_id)?;
        write_u64(writer, self.reserves_sats)?;
        write_u16(writer, self.script_pubkey.len() as u16)?;
        writer.write_all(&self.script_pubkey)?;
        write_bytes32(writer, &self.ledger_hash)?;
        write_bytes32(writer, &self.remote_ledger_hash)?;
        Ok(())
    }
}

impl WireDecode for UpdateReservesMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let channel_id = read_bytes32(reader)?;
        let reserves_sats = read_u64(reader)?;
        let script_len = read_u16(reader)? as usize;
        let mut script_pubkey = vec![0u8; script_len];
        reader.read_exact(&mut script_pubkey)?;
        let ledger_hash = read_bytes32(reader)?;
        let remote_ledger_hash = read_bytes32(reader)?;
        Ok(Self {
            channel_id,
            reserves_sats,
            script_pubkey,
            ledger_hash,
            remote_ledger_hash,
        })
    }
}

/// AcceptReserves message - response to UpdateReserves indicating acceptance
///
/// Sent by the counterparty after validating and accepting the proposed
/// reserves commitment via accept_extra_outputs_proposal().
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
}

impl WireEncode for AcceptReservesMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.channel_id)?;
        Ok(())
    }
}

impl WireDecode for AcceptReservesMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let channel_id = read_bytes32(reader)?;
        Ok(Self { channel_id })
    }
}

// ============================================================================
// Deposit Messages
// ============================================================================

/// deposit open message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOpenMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
    pub fees: Option<FeeStructure>,
    pub payment_hash: Option<[u8; 32]>,
    pub invoice: Option<String>,
    pub cosigner_guarantee_signature: Option<[u8; 64]>,
}

impl WireEncode for DepositOpenMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.pubkey)?;
        write_optional(writer, &self.fees, |w, f| f.wire_encode(w))?;
        write_optional(writer, &self.payment_hash, |w, h| write_bytes32(w, h))?;
        write_optional(writer, &self.invoice, |w, s| write_string(w, s))?;
        write_optional(writer, &self.cosigner_guarantee_signature, |w, s| write_bytes64(w, s))?;
        Ok(())
    }
}

impl WireDecode for DepositOpenMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            pubkey: read_pubkey(reader)?,
            fees: read_optional(reader, FeeStructure::wire_decode)?,
            payment_hash: read_optional(reader, read_bytes32)?,
            invoice: read_optional(reader, read_string)?,
            cosigner_guarantee_signature: read_optional(reader, read_bytes64)?,
        })
    }
}

/// deposit close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositCloseMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
}

impl WireEncode for DepositCloseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.pubkey)?;
        Ok(())
    }
}

impl WireDecode for DepositCloseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            pubkey: read_pubkey(reader)?,
        })
    }
}

/// fee change message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeChangeMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
    pub new_fees: FeeStructure,
}

impl WireEncode for FeeChangeMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.pubkey)?;
        self.new_fees.wire_encode(writer)?;
        Ok(())
    }
}

impl WireDecode for FeeChangeMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            pubkey: read_pubkey(reader)?,
            new_fees: FeeStructure::wire_decode(reader)?,
        })
    }
}

// ============================================================================
// Collateral Messages
// ============================================================================

// ============================================================================
// Fee and Ledger Close Messages
// ============================================================================

/// fee collect message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeCollectMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub block_height: u32,
}

impl WireEncode for FeeCollectMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.pubkey)?;
        write_u64(writer, self.amount)?;
        write_u32(writer, self.block_height)?;
        Ok(())
    }
}

impl WireDecode for FeeCollectMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            pubkey: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            block_height: read_u32(reader)?,
        })
    }
}

/// ledger close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerCloseMsg {
    pub reserves_id: String,
}

impl WireEncode for LedgerCloseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        Ok(())
    }
}

impl WireDecode for LedgerCloseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
        })
    }
}

// ============================================================================
// Payment Messages
// ============================================================================

/// receiving credit payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCreditPaymentMsg {
    pub payment_hash: [u8; 32],
    pub deposit_pubkey: PublicKey,
    pub amount: u64,
    pub invoice_id: String,
    pub reserves_id: String,
    pub sequence_number: u64,
}

impl WireEncode for ReceivingCreditPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.payment_hash)?;
        write_pubkey(writer, &self.deposit_pubkey)?;
        write_u64(writer, self.amount)?;
        write_string(writer, &self.invoice_id)?;
        write_string(writer, &self.reserves_id)?;
        write_u64(writer, self.sequence_number)?;
        Ok(())
    }
}

impl WireDecode for ReceivingCreditPaymentMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            payment_hash: read_bytes32(reader)?,
            deposit_pubkey: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            invoice_id: read_string(reader)?,
            reserves_id: read_string(reader)?,
            sequence_number: read_u64(reader)?,
        })
    }
}

/// sending lock payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingLockPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
    pub scriptpubkey_signature: [u8; 64],
}

impl WireEncode for SendingLockPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.pubkey)?;
        write_u64(writer, self.amount)?;
        write_bytes32(writer, &self.payment_id)?;
        write_u64(writer, self.sequence_number)?;
        write_bytes64(writer, &self.scriptpubkey_signature)?;
        Ok(())
    }
}

impl WireDecode for SendingLockPaymentMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            pubkey: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            payment_id: read_bytes32(reader)?,
            sequence_number: read_u64(reader)?,
            scriptpubkey_signature: read_bytes64(reader)?,
        })
    }
}

/// sending fail payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingFailPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
}

impl WireEncode for SendingFailPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.pubkey)?;
        write_u64(writer, self.amount)?;
        write_bytes32(writer, &self.payment_id)?;
        write_u64(writer, self.sequence_number)?;
        Ok(())
    }
}

impl WireDecode for SendingFailPaymentMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            pubkey: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            payment_id: read_bytes32(reader)?,
            sequence_number: read_u64(reader)?,
        })
    }
}

/// sending fulfill payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingFulfillPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
    pub scriptpubkey_signature: [u8; 64],
    pub preimage: [u8; 32],
}

impl WireEncode for SendingFulfillPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.pubkey)?;
        write_u64(writer, self.amount)?;
        write_bytes32(writer, &self.payment_id)?;
        write_u64(writer, self.sequence_number)?;
        write_bytes64(writer, &self.scriptpubkey_signature)?;
        write_bytes32(writer, &self.preimage)?;
        Ok(())
    }
}

impl WireDecode for SendingFulfillPaymentMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            pubkey: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            payment_id: read_bytes32(reader)?,
            sequence_number: read_u64(reader)?,
            scriptpubkey_signature: read_bytes64(reader)?,
            preimage: read_bytes32(reader)?,
        })
    }
}

/// receiving cosign invoice message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCosignInvoiceMsg {
    pub amount: u64,
    pub payment_hash: [u8; 32],
    pub expires: u64,
    pub assigned_deposit: PublicKey,
    pub invoice_id: String,
    pub bolt11: String,
}

impl WireEncode for ReceivingCosignInvoiceMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u64(writer, self.amount)?;
        write_bytes32(writer, &self.payment_hash)?;
        write_u64(writer, self.expires)?;
        write_pubkey(writer, &self.assigned_deposit)?;
        write_string(writer, &self.invoice_id)?;
        write_string(writer, &self.bolt11)?;
        Ok(())
    }
}

impl WireDecode for ReceivingCosignInvoiceMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            amount: read_u64(reader)?,
            payment_hash: read_bytes32(reader)?,
            expires: read_u64(reader)?,
            assigned_deposit: read_pubkey(reader)?,
            invoice_id: read_string(reader)?,
            bolt11: read_string(reader)?,
        })
    }
}

// ============================================================================
// Collateral Messages
// ============================================================================

/// quorum add member message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumAddMemberMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub quorum_member: PublicKey,
    pub quorum_member_signature: [u8; 64],
    /// The ledger ID where this member will lock collateral
    pub member_ledger_id: String,
}

impl WireEncode for QuorumAddMemberMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.quorum_member)?;
        write_bytes64(writer, &self.quorum_member_signature)?;
        write_string(writer, &self.member_ledger_id)?;
        Ok(())
    }
}

impl WireDecode for QuorumAddMemberMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            quorum_member: read_pubkey(reader)?,
            quorum_member_signature: read_bytes64(reader)?,
            member_ledger_id: read_string(reader)?,
        })
    }
}

/// quorum remove member message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumRemoveMemberMsg {
    pub reserves_id: String,
    pub quorum_member: PublicKey,
    pub operator_signature: [u8; 64],
}

impl WireEncode for QuorumRemoveMemberMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_string(writer, &self.reserves_id)?;
        write_pubkey(writer, &self.quorum_member)?;
        write_bytes64(writer, &self.operator_signature)?;
        Ok(())
    }
}

impl WireDecode for QuorumRemoveMemberMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            reserves_id: read_string(reader)?,
            quorum_member: read_pubkey(reader)?,
            operator_signature: read_bytes64(reader)?,
        })
    }
}

/// collateral attestation message
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollateralAttestationMsg {
    #[serde(with = "crate::types::serde_pubkey")]
    pub operator: PublicKey,
    #[serde(with = "crate::types::serde_pubkey")]
    pub quorum_member: PublicKey,
    /// The ledger ID where collateral is locked (must match member_ledger_id from QuorumAddMember)
    pub collateral_ledger_id: String,
    pub amount: u64,
    pub block_height: u32,
    #[serde(default)]
    pub lock_until_block: u32,
    #[serde(with = "crate::types::serde_64")]
    pub signature: [u8; 64],
    #[serde(with = "crate::types::serde_32")]
    pub ledger_hash: [u8; 32],
}

impl CollateralAttestationMsg {
    /// Get the available collateral amount
    pub fn available_collateral(&self) -> u64 {
        self.amount
    }
}

impl WireEncode for CollateralAttestationMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.quorum_member)?;
        write_string(writer, &self.collateral_ledger_id)?;
        write_u64(writer, self.amount)?;
        write_u32(writer, self.block_height)?;
        write_u32(writer, self.lock_until_block)?;
        write_bytes64(writer, &self.signature)?;
        write_bytes32(writer, &self.ledger_hash)?;
        Ok(())
    }
}

impl WireDecode for CollateralAttestationMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator: read_pubkey(reader)?,
            quorum_member: read_pubkey(reader)?,
            collateral_ledger_id: read_string(reader)?,
            amount: read_u64(reader)?,
            block_height: read_u32(reader)?,
            lock_until_block: read_u32(reader)?,
            signature: read_bytes64(reader)?,
            ledger_hash: read_bytes32(reader)?,
        })
    }
}

/// collateral consent request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentRequestMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub operator_signature: [u8; 64],
}

impl WireEncode for CollateralConsentRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_bytes64(writer, &self.operator_signature)?;
        Ok(())
    }
}

impl WireDecode for CollateralConsentRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            operator_signature: read_bytes64(reader)?,
        })
    }
}

/// collateral consent response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentResponseMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub consent_granted: bool,
    pub quorum_member_signature: [u8; 64],
}

impl WireEncode for CollateralConsentResponseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_u8(writer, self.consent_granted as u8)?;
        write_bytes64(writer, &self.quorum_member_signature)?;
        Ok(())
    }
}

impl WireDecode for CollateralConsentResponseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            consent_granted: read_u8(reader)? != 0,
            quorum_member_signature: read_bytes64(reader)?,
        })
    }
}

// ============================================================================
// Sync Messages
// ============================================================================

/// sync request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncRequestMsg {
    pub ledger_id: [u8; 32],
    pub last_known_sequence: u64,
}

impl WireEncode for SyncRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_32(writer, &self.ledger_id)?;
        write_u64(writer, self.last_known_sequence)?;
        Ok(())
    }
}

impl WireDecode for SyncRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            ledger_id: read_32(reader)?,
            last_known_sequence: read_u64(reader)?,
        })
    }
}

// ============================================================================
// Quorum Messages
// ============================================================================

/// quorum join request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinRequestMsgWire {
    pub requester_pubkey: PublicKey,
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub protocol_version: u16,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl WireEncode for QuorumJoinRequestMsgWire {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.requester_pubkey)?;
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_u16(writer, self.protocol_version)?;
        write_u64(writer, self.timestamp)?;
        write_bytes64(writer, &self.signature)?;
        Ok(())
    }
}

impl WireDecode for QuorumJoinRequestMsgWire {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            requester_pubkey: read_pubkey(reader)?,
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            protocol_version: read_u16(reader)?,
            timestamp: read_u64(reader)?,
            signature: read_bytes64(reader)?,
        })
    }
}

/// quorum join response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinResponseMsgWire {
    pub accepted: bool,
    pub members: Vec<PublicKey>,
    pub threshold: u16,
    pub last_sequence: u64,
    pub current_hash: [u8; 32],
    pub rejection_reason: Option<String>,
}

impl WireEncode for QuorumJoinResponseMsgWire {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u8(writer, self.accepted as u8)?;
        write_u16(writer, self.members.len() as u16)?;
        for pk in &self.members {
            write_pubkey(writer, pk)?;
        }
        write_u16(writer, self.threshold)?;
        write_u64(writer, self.last_sequence)?;
        write_bytes32(writer, &self.current_hash)?;
        write_optional(writer, &self.rejection_reason, |w, s| write_string(w, s))?;
        Ok(())
    }
}

impl WireDecode for QuorumJoinResponseMsgWire {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let accepted = read_u8(reader)? != 0;
        let count = read_u16(reader)? as usize;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(read_pubkey(reader)?);
        }
        Ok(Self {
            accepted,
            members,
            threshold: read_u16(reader)?,
            last_sequence: read_u64(reader)?,
            current_hash: read_bytes32(reader)?,
            rejection_reason: read_optional(reader, read_string)?,
        })
    }
}

/// quorum membership change message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMembershipChangeMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub change_type: String,
    pub member_pubkey: PublicKey,
    pub new_members: Vec<PublicKey>,
}

impl WireEncode for QuorumMembershipChangeMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_string(writer, &self.change_type)?;
        write_pubkey(writer, &self.member_pubkey)?;
        write_u16(writer, self.new_members.len() as u16)?;
        for pk in &self.new_members {
            write_pubkey(writer, pk)?;
        }
        Ok(())
    }
}

impl WireDecode for QuorumMembershipChangeMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let operator_id = read_pubkey(reader)?;
        let reserves_id = read_string(reader)?;
        let change_type = read_string(reader)?;
        let member_pubkey = read_pubkey(reader)?;
        let count = read_u16(reader)? as usize;
        let mut new_members = Vec::with_capacity(count);
        for _ in 0..count {
            new_members.push(read_pubkey(reader)?);
        }
        Ok(Self {
            operator_id,
            reserves_id,
            change_type,
            member_pubkey,
            new_members,
        })
    }
}

/// quorum state sync message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumStateSyncMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub updates: Vec<Vec<u8>>,
    pub start_sequence: u64,
    pub is_final: bool,
}

impl WireEncode for QuorumStateSyncMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_u16(writer, self.updates.len() as u16)?;
        for update in &self.updates {
            write_u32(writer, update.len() as u32)?;
            writer.write_all(update)?;
        }
        write_u64(writer, self.start_sequence)?;
        write_u8(writer, self.is_final as u8)?;
        Ok(())
    }
}

impl WireDecode for QuorumStateSyncMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let operator_id = read_pubkey(reader)?;
        let reserves_id = read_string(reader)?;
        let count = read_u16(reader)? as usize;
        let mut updates = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_u32(reader)? as usize;
            let mut update = vec![0u8; len];
            reader.read_exact(&mut update)?;
            updates.push(update);
        }
        Ok(Self {
            operator_id,
            reserves_id,
            updates,
            start_sequence: read_u64(reader)?,
            is_final: read_u8(reader)? != 0,
        })
    }
}

/// quorum vote request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteRequestMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub vote_round_id: [u8; 32],
    pub sequence_number: u64,
    pub state_hash: [u8; 32],
    pub claimed_reserves: u64,
    pub collateral_amounts: Vec<u64>,
    pub reserves_outpoint: Vec<u8>,
    pub destination_script: Vec<u8>,
    pub fee_rate_sat_vbyte: u64,
}

impl WireEncode for QuorumVoteRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_bytes32(writer, &self.vote_round_id)?;
        write_u64(writer, self.sequence_number)?;
        write_bytes32(writer, &self.state_hash)?;
        write_u64(writer, self.claimed_reserves)?;
        write_u16(writer, self.collateral_amounts.len() as u16)?;
        for amount in &self.collateral_amounts {
            write_u64(writer, *amount)?;
        }
        write_u16(writer, self.reserves_outpoint.len() as u16)?;
        writer.write_all(&self.reserves_outpoint)?;
        write_u16(writer, self.destination_script.len() as u16)?;
        writer.write_all(&self.destination_script)?;
        write_u64(writer, self.fee_rate_sat_vbyte)?;
        Ok(())
    }
}

impl WireDecode for QuorumVoteRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let operator_id = read_pubkey(reader)?;
        let reserves_id = read_string(reader)?;
        let vote_round_id = read_bytes32(reader)?;
        let sequence_number = read_u64(reader)?;
        let state_hash = read_bytes32(reader)?;
        let claimed_reserves = read_u64(reader)?;
        let coll_count = read_u16(reader)? as usize;
        let mut collateral_amounts = Vec::with_capacity(coll_count);
        for _ in 0..coll_count {
            collateral_amounts.push(read_u64(reader)?);
        }
        let outpoint_len = read_u16(reader)? as usize;
        let mut reserves_outpoint = vec![0u8; outpoint_len];
        reader.read_exact(&mut reserves_outpoint)?;
        let script_len = read_u16(reader)? as usize;
        let mut destination_script = vec![0u8; script_len];
        reader.read_exact(&mut destination_script)?;
        let fee_rate_sat_vbyte = read_u64(reader)?;
        Ok(Self {
            operator_id,
            reserves_id,
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

/// quorum vote message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteMsgWire {
    pub vote_round_id: [u8; 32],
    pub voter_pubkey: PublicKey,
    pub vote: bool,
    pub voter_sequence: u64,
    pub voter_state_hash: [u8; 32],
    pub evidence: Option<Vec<u8>>,
    pub signature: [u8; 64],
    pub spend_signature: Option<[u8; 64]>,
}

impl WireEncode for QuorumVoteMsgWire {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.vote_round_id)?;
        write_pubkey(writer, &self.voter_pubkey)?;
        write_u8(writer, self.vote as u8)?;
        write_u64(writer, self.voter_sequence)?;
        write_bytes32(writer, &self.voter_state_hash)?;
        // Write evidence as optional
        write_optional(writer, &self.evidence, |w, ev| {
            write_u32(w, ev.len() as u32)?;
            w.write_all(ev)?;
            Ok(())
        })?;
        write_bytes64(writer, &self.signature)?;
        // Write spend_signature as optional
        write_optional(writer, &self.spend_signature, |w, sig| write_bytes64(w, sig))?;
        Ok(())
    }
}

impl WireDecode for QuorumVoteMsgWire {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let vote_round_id = read_bytes32(reader)?;
        let voter_pubkey = read_pubkey(reader)?;
        let vote = read_u8(reader)? != 0;
        let voter_sequence = read_u64(reader)?;
        let voter_state_hash = read_bytes32(reader)?;
        // Read optional evidence
        let evidence = read_optional(reader, |r| {
            let len = read_u32(r)? as usize;
            let mut ev = vec![0u8; len];
            r.read_exact(&mut ev)?;
            Ok(ev)
        })?;
        let signature = read_bytes64(reader)?;
        // Read optional spend_signature
        let spend_signature = read_optional(reader, read_bytes64)?;
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
// Recovery Messages
// ============================================================================

/// recovery vote message
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

impl WireEncode for RecoveryVoteMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.partner)?;
        write_pubkey(writer, &self.voter)?;
        write_u8(writer, self.is_conforming as u8)?;
        write_bytes32(writer, &self.validated_hash)?;
        write_u64(writer, self.validated_sequence)?;
        write_optional(writer, &self.substitute_nomination, |w, pk| write_pubkey(w, pk))?;
        write_u8(writer, self.discovered_violation as u8)?;
        write_bytes64(writer, &self.signature)?;
        Ok(())
    }
}

impl WireDecode for RecoveryVoteMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator: read_pubkey(reader)?,
            partner: read_pubkey(reader)?,
            voter: read_pubkey(reader)?,
            is_conforming: read_u8(reader)? != 0,
            validated_hash: read_bytes32(reader)?,
            validated_sequence: read_u64(reader)?,
            substitute_nomination: read_optional(reader, read_pubkey)?,
            discovered_violation: read_u8(reader)? != 0,
            signature: read_bytes64(reader)?,
        })
    }
}

/// recovery claim request message
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

impl WireEncode for RecoveryClaimRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.partner)?;
        write_pubkey(writer, &self.claimant)?;
        write_u8(writer, self.tier_index)?;
        write_u32(writer, self.unsigned_tx.len() as u32)?;
        writer.write_all(&self.unsigned_tx)?;
        write_bytes32(writer, &self.sighash)?;
        write_u16(writer, self.destination_script.len() as u16)?;
        writer.write_all(&self.destination_script)?;
        write_u32(writer, self.block_height)?;
        Ok(())
    }
}

impl WireDecode for RecoveryClaimRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let operator = read_pubkey(reader)?;
        let partner = read_pubkey(reader)?;
        let claimant = read_pubkey(reader)?;
        let tier_index = read_u8(reader)?;
        let tx_len = read_u32(reader)? as usize;
        let mut unsigned_tx = vec![0u8; tx_len];
        reader.read_exact(&mut unsigned_tx)?;
        let sighash = read_bytes32(reader)?;
        let script_len = read_u16(reader)? as usize;
        let mut destination_script = vec![0u8; script_len];
        reader.read_exact(&mut destination_script)?;
        let block_height = read_u32(reader)?;
        Ok(Self {
            operator,
            partner,
            claimant,
            tier_index,
            unsigned_tx,
            sighash,
            destination_script,
            block_height,
        })
    }
}

/// recovery claim signature message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimSignatureMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub signer: PublicKey,
    pub sighash: [u8; 32],
    pub signature: [u8; 64],
}

impl WireEncode for RecoveryClaimSignatureMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.partner)?;
        write_pubkey(writer, &self.signer)?;
        write_bytes32(writer, &self.sighash)?;
        write_bytes64(writer, &self.signature)?;
        Ok(())
    }
}

impl WireDecode for RecoveryClaimSignatureMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator: read_pubkey(reader)?,
            partner: read_pubkey(reader)?,
            signer: read_pubkey(reader)?,
            sighash: read_bytes32(reader)?,
            signature: read_bytes64(reader)?,
        })
    }
}

/// recovery claim complete message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryClaimCompleteMsg {
    pub operator: PublicKey,
    pub partner: PublicKey,
    pub new_operator: PublicKey,
    pub claim_txid: [u8; 32],
    pub confirmation_block: u32,
    pub reason_code: u8,
}

impl WireEncode for RecoveryClaimCompleteMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.partner)?;
        write_pubkey(writer, &self.new_operator)?;
        write_bytes32(writer, &self.claim_txid)?;
        write_u32(writer, self.confirmation_block)?;
        write_u8(writer, self.reason_code)?;
        Ok(())
    }
}

impl WireDecode for RecoveryClaimCompleteMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator: read_pubkey(reader)?,
            partner: read_pubkey(reader)?,
            new_operator: read_pubkey(reader)?,
            claim_txid: read_bytes32(reader)?,
            confirmation_block: read_u32(reader)?,
            reason_code: read_u8(reader)?,
        })
    }
}

// ============================================================================
// Other Messages
// ============================================================================

/// uncredited payment message
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

impl WireEncode for UncreditedPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator)?;
        write_pubkey(writer, &self.partner)?;
        write_bytes32(writer, &self.payment_hash)?;
        write_bytes32(writer, &self.preimage)?;
        write_pubkey(writer, &self.deposit_pubkey)?;
        write_u64(writer, self.amount_msat)?;
        write_bytes64(writer, &self.invoice_cosignature)?;
        write_u64(writer, self.settlement_sequence)?;
        write_bytes32(writer, &self.settlement_ledger_hash)?;
        write_u32(writer, self.settlement_block_height)?;
        write_bytes64(writer, &self.accuser_signature)?;
        Ok(())
    }
}

impl WireDecode for UncreditedPaymentMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator: read_pubkey(reader)?,
            partner: read_pubkey(reader)?,
            payment_hash: read_bytes32(reader)?,
            preimage: read_bytes32(reader)?,
            deposit_pubkey: read_pubkey(reader)?,
            amount_msat: read_u64(reader)?,
            invoice_cosignature: read_bytes64(reader)?,
            settlement_sequence: read_u64(reader)?,
            settlement_ledger_hash: read_bytes32(reader)?,
            settlement_block_height: read_u32(reader)?,
            accuser_signature: read_bytes64(reader)?,
        })
    }
}

// ============================================================================
// Ledger Export Messages
// ============================================================================

/// Request to export a ledger for validation.
///
/// Sent by a partner or quorum member to request the complete ledger
/// history from the operator for conformance validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerExportRequestMsg {
    /// Operator's public key.
    pub operator_id: PublicKey,
    /// Reserves identifier for the ledger.
    pub reserves_id: String,
    /// Optional: only return updates after this sequence number.
    pub from_sequence: Option<u64>,
    /// Current block height (for export timestamp).
    pub block_height: u32,
}

impl WireEncode for LedgerExportRequestMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_optional(writer, &self.from_sequence, |w, seq| write_u64(w, *seq))?;
        write_u32(writer, self.block_height)?;
        Ok(())
    }
}

impl WireDecode for LedgerExportRequestMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            operator_id: read_pubkey(reader)?,
            reserves_id: read_string(reader)?,
            from_sequence: read_optional(reader, read_u64)?,
            block_height: read_u32(reader)?,
        })
    }
}

/// Response containing the ledger export data.
///
/// Contains the complete ledger history for validation, including
/// all signed updates and current state information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerExportResponseMsg {
    /// Operator's public key.
    pub operator_id: PublicKey,
    /// Reserves identifier for the ledger.
    pub reserves_id: String,
    /// Ledger address.
    pub ledger_address: String,
    /// Protocol version.
    pub version: u32,
    /// Export timestamp.
    pub exported_at: u64,
    /// Block height at export time.
    pub block_height: u32,
    /// Number of updates included.
    pub update_count: u32,
    /// Serialized updates (each update is length-prefixed).
    pub updates_data: Vec<u8>,
    /// Whether export was successful.
    pub success: bool,
    /// Error message if export failed.
    pub error_message: Option<String>,
}

impl WireEncode for LedgerExportResponseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.operator_id)?;
        write_string(writer, &self.reserves_id)?;
        write_string(writer, &self.ledger_address)?;
        write_u32(writer, self.version)?;
        write_u64(writer, self.exported_at)?;
        write_u32(writer, self.block_height)?;
        write_u32(writer, self.update_count)?;
        // Write updates data with length prefix
        write_u32(writer, self.updates_data.len() as u32)?;
        writer.write_all(&self.updates_data)?;
        write_u8(writer, if self.success { 1 } else { 0 })?;
        write_optional(writer, &self.error_message, |w, s| write_string(w, s))?;
        Ok(())
    }
}

impl WireDecode for LedgerExportResponseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let operator_id = read_pubkey(reader)?;
        let reserves_id = read_string(reader)?;
        let ledger_address = read_string(reader)?;
        let version = read_u32(reader)?;
        let exported_at = read_u64(reader)?;
        let block_height = read_u32(reader)?;
        let update_count = read_u32(reader)?;
        // Read updates data
        let updates_len = read_u32(reader)? as usize;
        let mut updates_data = vec![0u8; updates_len];
        reader.read_exact(&mut updates_data)?;
        let success = read_u8(reader)? != 0;
        let error_message = read_optional(reader, read_string)?;
        Ok(Self {
            operator_id,
            reserves_id,
            ledger_address,
            version,
            exported_at,
            block_height,
            update_count,
            updates_data,
            success,
            error_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_deposit_open_roundtrip() {
        let msg = DepositOpenMsg {
            reserves_id: test_pubkey(1).to_string(),
            pubkey: test_pubkey(2),
            fees: Some(FeeStructure {
                annualized_fixed: 1000,
                annualized_bps: 50,
                frequency_blocks: 144,
            }),
            payment_hash: Some([42u8; 32]),
            invoice: Some("lnbc1000n1ptest".to_string()),
            cosigner_guarantee_signature: None,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = DepositOpenMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_receiving_credit_payment_roundtrip() {
        let msg = ReceivingCreditPaymentMsg {
            payment_hash: [1u8; 32],
            deposit_pubkey: test_pubkey(2),
            amount: 50_000,
            invoice_id: "inv_123".to_string(),
            reserves_id: test_pubkey(1).to_string(),
            sequence_number: 42,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = ReceivingCreditPaymentMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_fee_structure_roundtrip() {
        let fees = FeeStructure {
            annualized_fixed: 5000,
            annualized_bps: 100,
            frequency_blocks: 288,
        };
        let bytes = fees.to_wire_bytes();
        let decoded = FeeStructure::from_wire_bytes(&bytes).unwrap();
        assert_eq!(fees, decoded);
    }

    #[test]
    fn test_ledger_export_request_roundtrip() {
        let msg = LedgerExportRequestMsg {
            operator_id: test_pubkey(1),
            reserves_id: test_pubkey(2).to_string(),
            from_sequence: Some(42),
            block_height: 100_000,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = LedgerExportRequestMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ledger_export_request_no_sequence() {
        let msg = LedgerExportRequestMsg {
            operator_id: test_pubkey(1),
            reserves_id: test_pubkey(2).to_string(),
            from_sequence: None,
            block_height: 100_000,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = LedgerExportRequestMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ledger_export_response_success_roundtrip() {
        let msg = LedgerExportResponseMsg {
            operator_id: test_pubkey(1),
            reserves_id: test_pubkey(2).to_string(),
            ledger_address: "tb1q...".to_string(),
            version: 1,
            exported_at: 1700000000,
            block_height: 100_000,
            update_count: 5,
            updates_data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            success: true,
            error_message: None,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = LedgerExportResponseMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ledger_export_response_error_roundtrip() {
        let msg = LedgerExportResponseMsg {
            operator_id: test_pubkey(1),
            reserves_id: test_pubkey(2).to_string(),
            ledger_address: "".to_string(),
            version: 1,
            exported_at: 1700000000,
            block_height: 100_000,
            update_count: 0,
            updates_data: vec![],
            success: false,
            error_message: Some("Ledger not found".to_string()),
        };
        let bytes = msg.to_wire_bytes();
        let decoded = LedgerExportResponseMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}
