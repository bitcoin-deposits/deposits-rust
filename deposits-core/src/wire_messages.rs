// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! V1 Wire Protocol Message Structs
//!
//! This module contains message structs for the V1 wire protocol format.
//! These are pure data types with LDK-independent serialization.
//!
//! ## Design
//!
//! - Structs are plain data with no LDK dependencies
//! - Serialization uses std::io traits
//! - LDK Readable/Writeable impls are provided separately in deposits-ldk

use bitcoin::secp256k1::PublicKey;
use std::io::{self, Read, Write};

use crate::types::FeeStructure;

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
// Reserves Messages
// ============================================================================

/// V1-compatible reserves increase message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesIncreaseMsg {
    pub partner_id: PublicKey,
    pub new_amount: u64,
}

impl WireEncode for ReservesIncreaseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_u64(writer, self.new_amount)?;
        Ok(())
    }
}

impl WireDecode for ReservesIncreaseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            new_amount: read_u64(reader)?,
        })
    }
}

/// V1-compatible reserves decrease message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesDecreaseMsg {
    pub partner_id: PublicKey,
    pub new_amount: u64,
}

impl WireEncode for ReservesDecreaseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_u64(writer, self.new_amount)?;
        Ok(())
    }
}

impl WireDecode for ReservesDecreaseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            new_amount: read_u64(reader)?,
        })
    }
}

/// V1-compatible reserves add output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesAddOutputMsg {
    pub initial_amount: u64,
    pub spend_to: PublicKey,
    pub partner_id: PublicKey,
    pub collateral_partners: Vec<PublicKey>,
}

impl WireEncode for ReservesAddOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_u64(writer, self.initial_amount)?;
        write_pubkey(writer, &self.spend_to)?;
        write_pubkey(writer, &self.partner_id)?;
        write_u16(writer, self.collateral_partners.len() as u16)?;
        for pk in &self.collateral_partners {
            write_pubkey(writer, pk)?;
        }
        Ok(())
    }
}

impl WireDecode for ReservesAddOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let initial_amount = read_u64(reader)?;
        let spend_to = read_pubkey(reader)?;
        let partner_id = read_pubkey(reader)?;
        let count = read_u16(reader)? as usize;
        let mut collateral_partners = Vec::with_capacity(count);
        for _ in 0..count {
            collateral_partners.push(read_pubkey(reader)?);
        }
        Ok(Self {
            initial_amount,
            spend_to,
            partner_id,
            collateral_partners,
        })
    }
}

/// V1-compatible reserves remove output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesRemoveOutputMsg {
    pub partner_id: PublicKey,
    pub remove_all: bool,
}

impl WireEncode for ReservesRemoveOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_u8(writer, self.remove_all as u8)?;
        Ok(())
    }
}

impl WireDecode for ReservesRemoveOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            remove_all: read_u8(reader)? != 0,
        })
    }
}

/// V1-compatible reserves update output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesUpdateOutputMsg {
    pub partner_id: PublicKey,
    pub spend_to: PublicKey,
}

impl WireEncode for ReservesUpdateOutputMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_pubkey(writer, &self.spend_to)?;
        Ok(())
    }
}

impl WireDecode for ReservesUpdateOutputMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            spend_to: read_pubkey(reader)?,
        })
    }
}

// ============================================================================
// Reserves Commitment Protocol Messages
// ============================================================================

/// UpdateReserves message - sent to propose reserves commitment to counterparty
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
    /// The reserves amount in satoshis
    pub reserves_amount: u64,
    /// The ledger hash to commit
    pub ledger_hash: [u8; 32],
    /// Reserves output scriptpubkey (serialized)
    pub reserves_script: Vec<u8>,
}

impl WireEncode for UpdateReservesMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.channel_id)?;
        write_u64(writer, self.reserves_amount)?;
        write_bytes32(writer, &self.ledger_hash)?;
        write_u16(writer, self.reserves_script.len() as u16)?;
        writer.write_all(&self.reserves_script)?;
        Ok(())
    }
}

impl WireDecode for UpdateReservesMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let channel_id = read_bytes32(reader)?;
        let reserves_amount = read_u64(reader)?;
        let ledger_hash = read_bytes32(reader)?;
        let script_len = read_u16(reader)? as usize;
        let mut reserves_script = vec![0u8; script_len];
        reader.read_exact(&mut reserves_script)?;
        Ok(Self {
            channel_id,
            reserves_amount,
            ledger_hash,
            reserves_script,
        })
    }
}

/// AcceptReserves message - sent to accept a reserves commitment proposal
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
    /// Whether the proposal is accepted
    pub accepted: bool,
}

impl WireEncode for AcceptReservesMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.channel_id)?;
        write_u8(writer, self.accepted as u8)?;
        Ok(())
    }
}

impl WireDecode for AcceptReservesMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            channel_id: read_bytes32(reader)?,
            accepted: read_u8(reader)? != 0,
        })
    }
}

// ============================================================================
// Deposit Messages
// ============================================================================

/// V1-compatible deposit open message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOpenMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
    pub fees: Option<FeeStructure>,
    pub payment_hash: Option<[u8; 32]>,
    pub invoice: Option<String>,
    pub cosigner_guarantee_signature: Option<[u8; 64]>,
}

impl WireEncode for DepositOpenMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
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
            partner_id: read_pubkey(reader)?,
            pubkey: read_pubkey(reader)?,
            fees: read_optional(reader, FeeStructure::wire_decode)?,
            payment_hash: read_optional(reader, read_bytes32)?,
            invoice: read_optional(reader, read_string)?,
            cosigner_guarantee_signature: read_optional(reader, read_bytes64)?,
        })
    }
}

/// V1-compatible deposit close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositCloseMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
}

impl WireEncode for DepositCloseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_pubkey(writer, &self.pubkey)?;
        Ok(())
    }
}

impl WireDecode for DepositCloseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            pubkey: read_pubkey(reader)?,
        })
    }
}

/// V1-compatible deposit update message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositUpdateMsg {
    pub partner_id: PublicKey,
    pub pubkey: PublicKey,
    pub new_fees: FeeStructure,
}

impl WireEncode for DepositUpdateMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_pubkey(writer, &self.pubkey)?;
        self.new_fees.wire_encode(writer)?;
        Ok(())
    }
}

impl WireDecode for DepositUpdateMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            pubkey: read_pubkey(reader)?,
            new_fees: FeeStructure::wire_decode(reader)?,
        })
    }
}

// ============================================================================
// Collateral Messages
// ============================================================================

/// V1-compatible collateral increase message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralIncreaseMsg {
    pub partner_id: PublicKey,
    pub new_amount: u64,
}

impl WireEncode for CollateralIncreaseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_u64(writer, self.new_amount)?;
        Ok(())
    }
}

impl WireDecode for CollateralIncreaseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            new_amount: read_u64(reader)?,
        })
    }
}

/// V1-compatible collateral decrease message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralDecreaseMsg {
    pub partner_id: PublicKey,
    pub new_amount: u64,
}

impl WireEncode for CollateralDecreaseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_u64(writer, self.new_amount)?;
        Ok(())
    }
}

impl WireDecode for CollateralDecreaseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            new_amount: read_u64(reader)?,
        })
    }
}

// ============================================================================
// Fee and Ledger Close Messages
// ============================================================================

/// V1-compatible fee collect message
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

/// V1-compatible ledger close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerCloseMsg {
    pub partner_id: PublicKey,
}

impl WireEncode for LedgerCloseMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        Ok(())
    }
}

impl WireDecode for LedgerCloseMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
        })
    }
}

// ============================================================================
// Payment Messages
// ============================================================================

/// V1-compatible receiving credit payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCreditPaymentMsg {
    pub payment_hash: [u8; 32],
    pub deposit_pubkey: PublicKey,
    pub amount: u64,
    pub invoice_id: String,
    pub partner_id: PublicKey,
    pub sequence_number: u64,
}

impl WireEncode for ReceivingCreditPaymentMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_bytes32(writer, &self.payment_hash)?;
        write_pubkey(writer, &self.deposit_pubkey)?;
        write_u64(writer, self.amount)?;
        write_string(writer, &self.invoice_id)?;
        write_pubkey(writer, &self.partner_id)?;
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
            partner_id: read_pubkey(reader)?,
            sequence_number: read_u64(reader)?,
        })
    }
}

/// V1-compatible sending lock payment message
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

/// V1-compatible sending fail payment message
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

/// V1-compatible sending fulfill payment message
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

/// V1-compatible receiving cosign invoice message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCosignInvoiceMsg {
    pub partner_id: PublicKey,
    pub assigned_deposit: PublicKey,
    pub amount: u64,
    pub payment_hash: [u8; 32],
    pub invoice_id: String,
}

impl WireEncode for ReceivingCosignInvoiceMsg {
    fn wire_encode<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        write_pubkey(writer, &self.partner_id)?;
        write_pubkey(writer, &self.assigned_deposit)?;
        write_u64(writer, self.amount)?;
        write_bytes32(writer, &self.payment_hash)?;
        write_string(writer, &self.invoice_id)?;
        Ok(())
    }
}

impl WireDecode for ReceivingCosignInvoiceMsg {
    fn wire_decode<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        Ok(Self {
            partner_id: read_pubkey(reader)?,
            assigned_deposit: read_pubkey(reader)?,
            amount: read_u64(reader)?,
            payment_hash: read_bytes32(reader)?,
            invoice_id: read_string(reader)?,
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
    fn test_reserves_increase_roundtrip() {
        let msg = ReservesIncreaseMsg {
            partner_id: test_pubkey(1),
            new_amount: 100_000,
        };
        let bytes = msg.to_wire_bytes();
        let decoded = ReservesIncreaseMsg::from_wire_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_deposit_open_roundtrip() {
        let msg = DepositOpenMsg {
            partner_id: test_pubkey(1),
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
            partner_id: test_pubkey(1),
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
}
