// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Wire Format Type Wrappers
//!
//! This module provides newtype wrappers around `deposits-core` types that add
//! LDK's `Readable` and `Writeable` trait implementations for wire protocol
//! serialization.
//!
//! The pattern is:
//! - `deposits_core::FeeStructure` - pure data type with TLV encoding
//! - `deposits_ldk::wire::FeeStructure` - wrapper with LDK Readable/Writeable
//!
//! This allows the core protocol to remain LDK-agnostic while providing
//! seamless integration with LDK's serialization infrastructure.

use bitcoin::secp256k1::PublicKey;
use deposits_core::tlv::{TlvDecode, TlvEncode};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

// ============================================================================
// FeeStructure Wrapper
// ============================================================================

/// Fee structure - wraps core type with LDK serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeeStructure(pub deposits_core::FeeStructure);

impl FeeStructure {
    /// Create a new fee structure.
    pub fn new(annualized_fixed: u64, annualized_bps: u16, frequency_blocks: u32) -> Self {
        FeeStructure(deposits_core::FeeStructure {
            annualized_fixed,
            annualized_bps,
            frequency_blocks,
        })
    }
}

impl Default for FeeStructure {
    fn default() -> Self {
        FeeStructure(deposits_core::FeeStructure::default())
    }
}

impl Deref for FeeStructure {
    type Target = deposits_core::FeeStructure;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FeeStructure {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::FeeStructure> for FeeStructure {
    fn from(core: deposits_core::FeeStructure) -> Self {
        FeeStructure(core)
    }
}

impl From<FeeStructure> for deposits_core::FeeStructure {
    fn from(local: FeeStructure) -> Self {
        local.0
    }
}

impl Writeable for FeeStructure {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let bytes = self.0.tlv_encode();
        (bytes.len() as u16).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for FeeStructure {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::ShortRead)?;
        deposits_core::FeeStructure::tlv_decode(&bytes)
            .map(FeeStructure)
            .map_err(|_| DecodeError::InvalidValue)
    }
}

// ============================================================================
// ReservesOutput Wrapper
// ============================================================================

/// Reserves output - wraps core type with LDK serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservesOutput(pub deposits_core::ReservesOutput);

impl ReservesOutput {
    /// Create a new reserves output.
    pub fn new(channel_id: [u8; 32], amount: u64, spend_to: PublicKey) -> Self {
        ReservesOutput(deposits_core::ReservesOutput {
            channel_id,
            amount,
            spend_to,
        })
    }
}

impl Default for ReservesOutput {
    fn default() -> Self {
        ReservesOutput(deposits_core::ReservesOutput::default())
    }
}

impl Deref for ReservesOutput {
    type Target = deposits_core::ReservesOutput;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ReservesOutput {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::ReservesOutput> for ReservesOutput {
    fn from(core: deposits_core::ReservesOutput) -> Self {
        ReservesOutput(core)
    }
}

impl From<ReservesOutput> for deposits_core::ReservesOutput {
    fn from(local: ReservesOutput) -> Self {
        local.0
    }
}

impl Writeable for ReservesOutput {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let bytes = self.0.tlv_encode();
        (bytes.len() as u16).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for ReservesOutput {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::ShortRead)?;
        deposits_core::ReservesOutput::tlv_decode(&bytes)
            .map(ReservesOutput)
            .map_err(|_| DecodeError::InvalidValue)
    }
}

// ============================================================================
// Invoice Wrapper
// ============================================================================

/// Invoice - wraps core type with LDK serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Invoice(pub deposits_core::Invoice);

impl Invoice {
    /// Create a new invoice.
    pub fn new(
        id: String,
        payment_hash: [u8; 32],
        amount: u64,
        expires: u64,
        assigned_deposit: PublicKey,
        bolt11: String,
    ) -> Self {
        Invoice(deposits_core::Invoice {
            id,
            payment_hash,
            amount,
            expires,
            assigned_deposit,
            bolt11,
        })
    }
}

impl Deref for Invoice {
    type Target = deposits_core::Invoice;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Invoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::Invoice> for Invoice {
    fn from(core: deposits_core::Invoice) -> Self {
        Invoice(core)
    }
}

impl From<Invoice> for deposits_core::Invoice {
    fn from(local: Invoice) -> Self {
        local.0
    }
}

impl Writeable for Invoice {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let bytes = self.0.tlv_encode();
        (bytes.len() as u16).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for Invoice {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::ShortRead)?;
        deposits_core::Invoice::tlv_decode(&bytes)
            .map(Invoice)
            .map_err(|_| DecodeError::InvalidValue)
    }
}

// ============================================================================
// PendingInvoice Wrapper
// ============================================================================

/// Pending invoice - wraps core type with LDK serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PendingInvoice(pub deposits_core::PendingInvoice);

impl PendingInvoice {
    /// Create a new pending invoice.
    pub fn new(
        amount: u64,
        payment_hash: [u8; 32],
        expires: u64,
        assigned_deposit: PublicKey,
        invoice_id: String,
        bolt11: String,
    ) -> Self {
        PendingInvoice(deposits_core::PendingInvoice {
            amount,
            payment_hash,
            expires,
            assigned_deposit,
            invoice_id,
            bolt11,
        })
    }
}

impl Deref for PendingInvoice {
    type Target = deposits_core::PendingInvoice;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PendingInvoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::PendingInvoice> for PendingInvoice {
    fn from(core: deposits_core::PendingInvoice) -> Self {
        PendingInvoice(core)
    }
}

impl From<PendingInvoice> for deposits_core::PendingInvoice {
    fn from(local: PendingInvoice) -> Self {
        local.0
    }
}

impl Writeable for PendingInvoice {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let bytes = self.0.tlv_encode();
        (bytes.len() as u16).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for PendingInvoice {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::ShortRead)?;
        deposits_core::PendingInvoice::tlv_decode(&bytes)
            .map(PendingInvoice)
            .map_err(|_| DecodeError::InvalidValue)
    }
}

// ============================================================================
// Deposit Wrapper
// ============================================================================

/// Deposit - wraps core type with LDK serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Deposit(pub deposits_core::Deposit);

impl Deposit {
    /// Create a new deposit.
    pub fn new(pubkey: PublicKey, fees: Option<deposits_core::FeeStructure>) -> Self {
        Deposit(deposits_core::Deposit::new(pubkey, fees))
    }
}

impl Default for Deposit {
    fn default() -> Self {
        // Use a valid but arbitrary pubkey for default
        let default_pubkey = PublicKey::from_slice(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1,
        ])
        .unwrap();

        Deposit(deposits_core::Deposit::new(default_pubkey, None))
    }
}

impl Deref for Deposit {
    type Target = deposits_core::Deposit;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Deposit {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::Deposit> for Deposit {
    fn from(core: deposits_core::Deposit) -> Self {
        Deposit(core)
    }
}

impl From<Deposit> for deposits_core::Deposit {
    fn from(local: Deposit) -> Self {
        local.0
    }
}

impl Writeable for Deposit {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let bytes = self.0.tlv_encode();
        (bytes.len() as u16).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for Deposit {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| DecodeError::ShortRead)?;
        deposits_core::Deposit::tlv_decode(&bytes)
            .map(Deposit)
            .map_err(|_| DecodeError::InvalidValue)
    }
}

// ============================================================================
// LedgerState Wrapper
// ============================================================================

/// LedgerState wrapper with LDK Readable/Writeable using TLV encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LedgerState(pub deposits_core::LedgerState);

impl LedgerState {
    /// Create a new empty ledger state.
    pub fn new(operator_key: PublicKey, reserves_key: PublicKey, ledger_address: String, genesis_block: u32) -> Self {
        LedgerState(deposits_core::LedgerState::new(operator_key, reserves_key.to_string(), ledger_address, genesis_block))
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        // Use a valid but arbitrary pubkey for default
        let default_pubkey = PublicKey::from_slice(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1,
        ])
        .unwrap();
        LedgerState::new(default_pubkey, default_pubkey, String::new(), 0)
    }
}

impl Deref for LedgerState {
    type Target = deposits_core::LedgerState;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for LedgerState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::LedgerState> for LedgerState {
    fn from(inner: deposits_core::LedgerState) -> Self {
        LedgerState(inner)
    }
}

impl Writeable for LedgerState {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        // Use JSON serialization for complex nested types
        // This is simpler than implementing field-by-field TLV for all nested HashMaps
        let json = serde_json::to_vec(&self.0)
            .map_err(|_| lightning::io::Error::new(lightning::io::ErrorKind::InvalidData, "JSON encode failed"))?;
        (json.len() as u32).write(writer)?;
        writer.write_all(&json)?;
        Ok(())
    }
}

impl Readable for LedgerState {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u32 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        let inner: deposits_core::LedgerState = serde_json::from_slice(&bytes)
            .map_err(|_| DecodeError::InvalidValue)?;
        Ok(LedgerState(inner))
    }
}

// ============================================================================
// SignedLedgerUpdate Wrapper
// ============================================================================

/// SignedLedgerUpdate wrapper with LDK Readable/Writeable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedLedgerUpdate(pub deposits_core::SignedLedgerUpdate);

impl Deref for SignedLedgerUpdate {
    type Target = deposits_core::SignedLedgerUpdate;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignedLedgerUpdate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::SignedLedgerUpdate> for SignedLedgerUpdate {
    fn from(inner: deposits_core::SignedLedgerUpdate) -> Self {
        SignedLedgerUpdate(inner)
    }
}

impl From<SignedLedgerUpdate> for deposits_core::SignedLedgerUpdate {
    fn from(wrapper: SignedLedgerUpdate) -> Self {
        wrapper.0
    }
}

impl Writeable for SignedLedgerUpdate {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let json = serde_json::to_vec(&self.0)
            .map_err(|_| lightning::io::Error::new(lightning::io::ErrorKind::InvalidData, "JSON encode failed"))?;
        (json.len() as u32).write(writer)?;
        writer.write_all(&json)?;
        Ok(())
    }
}

impl Readable for SignedLedgerUpdate {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u32 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        let inner: deposits_core::SignedLedgerUpdate = serde_json::from_slice(&bytes)
            .map_err(|_| DecodeError::InvalidValue)?;
        Ok(SignedLedgerUpdate(inner))
    }
}

// ============================================================================
// SignedLedgerUpdateLog Wrapper
// ============================================================================

/// SignedLedgerUpdateLog wrapper with LDK Readable/Writeable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedLedgerUpdateLog(pub deposits_core::SignedLedgerUpdateLog);

impl Deref for SignedLedgerUpdateLog {
    type Target = deposits_core::SignedLedgerUpdateLog;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignedLedgerUpdateLog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<deposits_core::SignedLedgerUpdateLog> for SignedLedgerUpdateLog {
    fn from(inner: deposits_core::SignedLedgerUpdateLog) -> Self {
        SignedLedgerUpdateLog(inner)
    }
}

impl Writeable for SignedLedgerUpdateLog {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        let json = serde_json::to_vec(&self.0)
            .map_err(|_| lightning::io::Error::new(lightning::io::ErrorKind::InvalidData, "JSON encode failed"))?;
        (json.len() as u32).write(writer)?;
        writer.write_all(&json)?;
        Ok(())
    }
}

impl Readable for SignedLedgerUpdateLog {
    fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let len: u32 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        let inner: deposits_core::SignedLedgerUpdateLog = serde_json::from_slice(&bytes)
            .map_err(|_| DecodeError::InvalidValue)?;
        Ok(SignedLedgerUpdateLog(inner))
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

    #[test]
    fn test_fee_structure_roundtrip() {
        let original = FeeStructure::new(1000, 50, 144);
        let mut buffer = Vec::new();
        original.write(&mut buffer).unwrap();

        let mut reader = &buffer[..];
        let decoded = FeeStructure::read(&mut reader).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_reserves_output_roundtrip() {
        let pubkey = test_pubkey();
        let original = ReservesOutput::new([1u8; 32], 50000, pubkey);
        let mut buffer = Vec::new();
        original.write(&mut buffer).unwrap();

        let mut reader = &buffer[..];
        let decoded = ReservesOutput::read(&mut reader).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invoice_roundtrip() {
        let pubkey = test_pubkey();
        let original = Invoice::new(
            "inv123".to_string(),
            [2u8; 32],
            100000,
            1700000000,
            pubkey,
            "lnbc...".to_string(),
        );
        let mut buffer = Vec::new();
        original.write(&mut buffer).unwrap();

        let mut reader = &buffer[..];
        let decoded = Invoice::read(&mut reader).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_pending_invoice_roundtrip() {
        let pubkey = test_pubkey();
        let original = PendingInvoice::new(
            50000,
            [3u8; 32],
            1700000000,
            pubkey,
            "pending123".to_string(),
            "lnbc...".to_string(),
        );
        let mut buffer = Vec::new();
        original.write(&mut buffer).unwrap();

        let mut reader = &buffer[..];
        let decoded = PendingInvoice::read(&mut reader).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_roundtrip() {
        let pubkey = test_pubkey();
        let mut original = Deposit::new(pubkey, Some(FeeStructure::new(500, 25, 144).into()));
        original.balance = 100000;
        original.locked_balance = 5000;
        original.invoices.push(deposits_core::Invoice {
            id: "inv1".to_string(),
            payment_hash: [4u8; 32],
            amount: 50000,
            expires: 1700000000,
            assigned_deposit: pubkey,
            bolt11: "lnbc...".to_string(),
        });
        original.last_fee_assessment = 800000;
        let mut buffer = Vec::new();
        original.write(&mut buffer).unwrap();

        let mut reader = &buffer[..];
        let decoded = Deposit::read(&mut reader).unwrap();

        assert_eq!(original, decoded);
    }
}
