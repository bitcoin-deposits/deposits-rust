// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! # TLV (Type-Length-Value) Codec
//!
//! A lightweight, LDK-independent TLV encoding implementation for the Bitcoin Deposits protocol.
//! This provides forward-compatible serialization without requiring Lightning implementation
//! dependencies.
//!
//! ## Format
//!
//! Each TLV record consists of:
//! - **Type**: BigEndian varint identifying the field
//! - **Length**: BigEndian varint specifying value length in bytes
//! - **Value**: The encoded field data
//!
//! ## Design Principles
//!
//! - **Forward compatible**: Unknown fields are preserved, not rejected
//! - **Canonical ordering**: Fields sorted by type for deterministic encoding
//! - **Required vs Optional**: Even types are required, odd types are optional
//! - **No LDK dependency**: Pure Rust implementation

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};

/// Error types for TLV encoding/decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// Unexpected end of data while reading
    UnexpectedEof,
    /// A required field is missing
    MissingRequiredField { field_type: u64 },
    /// Field value is invalid
    InvalidFieldValue { field_type: u64, reason: String },
    /// Duplicate field type encountered
    DuplicateField { field_type: u64 },
    /// Fields not in canonical order
    NonCanonicalOrder { field_type: u64 },
    /// IO error during read/write
    IoError(String),
    /// Invalid varint encoding
    InvalidVarint,
    /// Field type overflow
    TypeOverflow,
}

impl std::fmt::Display for TlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvError::UnexpectedEof => write!(f, "unexpected end of TLV data"),
            TlvError::MissingRequiredField { field_type } => {
                write!(f, "missing required TLV field type {}", field_type)
            }
            TlvError::InvalidFieldValue { field_type, reason } => {
                write!(f, "invalid value for TLV field {}: {}", field_type, reason)
            }
            TlvError::DuplicateField { field_type } => {
                write!(f, "duplicate TLV field type {}", field_type)
            }
            TlvError::NonCanonicalOrder { field_type } => {
                write!(f, "TLV field {} not in canonical order", field_type)
            }
            TlvError::IoError(e) => write!(f, "TLV IO error: {}", e),
            TlvError::InvalidVarint => write!(f, "invalid varint encoding"),
            TlvError::TypeOverflow => write!(f, "TLV type value overflow"),
        }
    }
}

impl std::error::Error for TlvError {}

impl From<io::Error> for TlvError {
    fn from(e: io::Error) -> Self {
        TlvError::IoError(e.to_string())
    }
}

/// Result type for TLV operations
pub type TlvResult<T> = Result<T, TlvError>;

// ============================================================================
// Varint Encoding (BigEndian, compatible with Lightning TLV)
// ============================================================================

/// Write a varint (BigEndian, 1/3/5/9 byte encoding)
pub fn write_varint<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    if value < 0xfd {
        writer.write_all(&[value as u8])
    } else if value <= 0xffff {
        writer.write_all(&[0xfd])?;
        writer.write_all(&(value as u16).to_be_bytes())
    } else if value <= 0xffffffff {
        writer.write_all(&[0xfe])?;
        writer.write_all(&(value as u32).to_be_bytes())
    } else {
        writer.write_all(&[0xff])?;
        writer.write_all(&value.to_be_bytes())
    }
}

/// Read a varint (BigEndian, 1/3/5/9 byte encoding)
pub fn read_varint<R: Read>(reader: &mut R) -> TlvResult<u64> {
    let mut first = [0u8; 1];
    reader
        .read_exact(&mut first)
        .map_err(|_| TlvError::UnexpectedEof)?;

    match first[0] {
        0..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|_| TlvError::UnexpectedEof)?;
            let val = u16::from_be_bytes(buf);
            if val < 0xfd {
                return Err(TlvError::InvalidVarint);
            }
            Ok(val as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .map_err(|_| TlvError::UnexpectedEof)?;
            let val = u32::from_be_bytes(buf);
            if val <= 0xffff {
                return Err(TlvError::InvalidVarint);
            }
            Ok(val as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            reader
                .read_exact(&mut buf)
                .map_err(|_| TlvError::UnexpectedEof)?;
            let val = u64::from_be_bytes(buf);
            if val <= 0xffffffff {
                return Err(TlvError::InvalidVarint);
            }
            Ok(val)
        }
    }
}

// ============================================================================
// TLV Stream
// ============================================================================

/// A collection of TLV records that can be encoded/decoded
#[derive(Debug, Clone, Default)]
pub struct TlvStream {
    /// Fields stored by type (BTreeMap ensures canonical ordering)
    fields: BTreeMap<u64, Vec<u8>>,
}

impl TlvStream {
    /// Create an empty TLV stream
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    /// Insert a field value
    pub fn insert(&mut self, field_type: u64, value: Vec<u8>) {
        self.fields.insert(field_type, value);
    }

    /// Get a field value
    pub fn get(&self, field_type: u64) -> Option<&[u8]> {
        self.fields.get(&field_type).map(|v| v.as_slice())
    }

    /// Remove and return a field value
    pub fn take(&mut self, field_type: u64) -> Option<Vec<u8>> {
        self.fields.remove(&field_type)
    }

    /// Check if a field exists
    pub fn contains(&self, field_type: u64) -> bool {
        self.fields.contains_key(&field_type)
    }

    /// Encode the TLV stream to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write(&mut buf).expect("vec write cannot fail");
        buf
    }

    /// Write the TLV stream to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // BTreeMap iteration is already in sorted order
        for (&field_type, value) in &self.fields {
            write_varint(writer, field_type)?;
            write_varint(writer, value.len() as u64)?;
            writer.write_all(value)?;
        }
        Ok(())
    }

    /// Decode a TLV stream from bytes
    pub fn decode(data: &[u8]) -> TlvResult<Self> {
        let mut cursor = Cursor::new(data);
        Self::read(&mut cursor)
    }

    /// Read a TLV stream from a reader
    pub fn read<R: Read>(reader: &mut R) -> TlvResult<Self> {
        let mut stream = TlvStream::new();
        let mut last_type: Option<u64> = None;

        loop {
            // Try to read field type
            let field_type = match read_varint(reader) {
                Ok(t) => t,
                Err(TlvError::UnexpectedEof) => break, // Normal end of stream
                Err(e) => return Err(e),
            };

            // Check canonical ordering
            if let Some(last) = last_type {
                if field_type <= last {
                    return Err(TlvError::NonCanonicalOrder { field_type });
                }
            }
            last_type = Some(field_type);

            // Check for duplicates (shouldn't happen with ordering check, but be safe)
            if stream.contains(field_type) {
                return Err(TlvError::DuplicateField { field_type });
            }

            // Read length and value
            let length = read_varint(reader)?;

            // Sanity check to prevent capacity overflow from malformed data
            // 16MB should be more than enough for any legitimate TLV value
            const MAX_TLV_VALUE_LENGTH: u64 = 16 * 1024 * 1024;
            if length > MAX_TLV_VALUE_LENGTH {
                return Err(TlvError::InvalidFieldValue {
                    field_type,
                    reason: format!(
                        "TLV value length {} exceeds maximum {}",
                        length, MAX_TLV_VALUE_LENGTH
                    ),
                });
            }
            let mut value = vec![0u8; length as usize];
            reader
                .read_exact(&mut value)
                .map_err(|_| TlvError::UnexpectedEof)?;

            stream.insert(field_type, value);
        }

        Ok(stream)
    }

    /// Get iterator over all fields
    pub fn iter(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.fields.iter().map(|(&k, v)| (k, v.as_slice()))
    }
}

// ============================================================================
// TLV Encode/Decode Traits
// ============================================================================

/// Trait for types that can be encoded to TLV format
pub trait TlvEncode {
    /// Encode this value to a TLV stream
    fn tlv_encode(&self) -> Vec<u8>;

    /// Write this value in TLV format to a writer
    fn tlv_write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.tlv_encode())
    }
}

/// Trait for types that can be decoded from TLV format
pub trait TlvDecode: Sized {
    /// Decode from TLV bytes
    fn tlv_decode(data: &[u8]) -> TlvResult<Self>;

    /// Read from TLV format
    fn tlv_read<R: Read>(reader: &mut R) -> TlvResult<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Self::tlv_decode(&buf)
    }
}

// ============================================================================
// Primitive Type Encoding Helpers
// ============================================================================

/// Encode a u8 to bytes
pub fn encode_u8(value: u8) -> Vec<u8> {
    vec![value]
}

/// Decode a u8 from bytes
pub fn decode_u8(data: &[u8]) -> TlvResult<u8> {
    if data.len() != 1 {
        return Err(TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("expected 1 byte for u8, got {}", data.len()),
        });
    }
    Ok(data[0])
}

/// Encode a u16 to bytes (BigEndian)
pub fn encode_u16(value: u16) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decode a u16 from bytes (BigEndian)
pub fn decode_u16(data: &[u8]) -> TlvResult<u16> {
    if data.len() != 2 {
        return Err(TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("expected 2 bytes for u16, got {}", data.len()),
        });
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Encode a u32 to bytes (BigEndian)
pub fn encode_u32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decode a u32 from bytes (BigEndian)
pub fn decode_u32(data: &[u8]) -> TlvResult<u32> {
    if data.len() != 4 {
        return Err(TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("expected 4 bytes for u32, got {}", data.len()),
        });
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Encode a u64 to bytes (BigEndian)
pub fn encode_u64(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decode a u64 from bytes (BigEndian)
pub fn decode_u64(data: &[u8]) -> TlvResult<u64> {
    if data.len() != 8 {
        return Err(TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("expected 8 bytes for u64, got {}", data.len()),
        });
    }
    Ok(u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

/// Encode a string to bytes (UTF-8)
pub fn encode_string(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Decode a string from bytes (UTF-8)
pub fn decode_string(data: &[u8]) -> TlvResult<String> {
    String::from_utf8(data.to_vec()).map_err(|e| TlvError::InvalidFieldValue {
        field_type: 0,
        reason: format!("invalid UTF-8: {}", e),
    })
}

/// Encode a fixed-size byte array
pub fn encode_bytes(value: &[u8]) -> Vec<u8> {
    value.to_vec()
}

/// Decode a fixed-size byte array
pub fn decode_bytes<const N: usize>(data: &[u8]) -> TlvResult<[u8; N]> {
    if data.len() != N {
        return Err(TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("expected {} bytes, got {}", N, data.len()),
        });
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(data);
    Ok(arr)
}

/// Encode a PublicKey (33 bytes compressed)
pub fn encode_pubkey(pubkey: &bitcoin::secp256k1::PublicKey) -> Vec<u8> {
    pubkey.serialize().to_vec()
}

/// Decode a PublicKey (33 bytes compressed)
pub fn decode_pubkey(data: &[u8]) -> TlvResult<bitcoin::secp256k1::PublicKey> {
    bitcoin::secp256k1::PublicKey::from_slice(data).map_err(|e| TlvError::InvalidFieldValue {
        field_type: 0,
        reason: format!("invalid pubkey: {}", e),
    })
}

/// Encode a Signature (64 bytes)
pub fn encode_signature(sig: &bitcoin::secp256k1::ecdsa::Signature) -> Vec<u8> {
    sig.serialize_compact().to_vec()
}

/// Decode a Signature (64 bytes)
pub fn decode_signature(data: &[u8]) -> TlvResult<bitcoin::secp256k1::ecdsa::Signature> {
    bitcoin::secp256k1::ecdsa::Signature::from_compact(data).map_err(|e| {
        TlvError::InvalidFieldValue {
            field_type: 0,
            reason: format!("invalid signature: {}", e),
        }
    })
}

// ============================================================================
// TLV Builder (fluent API for encoding)
// ============================================================================

/// Builder for constructing TLV streams
#[derive(Debug, Default)]
pub struct TlvBuilder {
    stream: TlvStream,
}

impl TlvBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a u8 field
    pub fn u8_field(mut self, field_type: u64, value: u8) -> Self {
        self.stream.insert(field_type, encode_u8(value));
        self
    }

    /// Add a u16 field
    pub fn u16_field(mut self, field_type: u64, value: u16) -> Self {
        self.stream.insert(field_type, encode_u16(value));
        self
    }

    /// Add a u32 field
    pub fn u32_field(mut self, field_type: u64, value: u32) -> Self {
        self.stream.insert(field_type, encode_u32(value));
        self
    }

    /// Add a u64 field
    pub fn u64_field(mut self, field_type: u64, value: u64) -> Self {
        self.stream.insert(field_type, encode_u64(value));
        self
    }

    /// Add a string field
    pub fn string_field(mut self, field_type: u64, value: &str) -> Self {
        self.stream.insert(field_type, encode_string(value));
        self
    }

    /// Add a bytes field
    pub fn bytes_field(mut self, field_type: u64, value: &[u8]) -> Self {
        self.stream.insert(field_type, encode_bytes(value));
        self
    }

    /// Add a pubkey field
    pub fn pubkey_field(mut self, field_type: u64, value: &bitcoin::secp256k1::PublicKey) -> Self {
        self.stream.insert(field_type, encode_pubkey(value));
        self
    }

    /// Add a signature field
    pub fn signature_field(
        mut self,
        field_type: u64,
        value: &bitcoin::secp256k1::ecdsa::Signature,
    ) -> Self {
        self.stream.insert(field_type, encode_signature(value));
        self
    }

    /// Add an optional field (only if Some)
    pub fn optional<T, F>(self, field_type: u64, value: &Option<T>, encoder: F) -> Self
    where
        F: FnOnce(&T) -> Vec<u8>,
    {
        match value {
            Some(v) => {
                let mut s = self;
                s.stream.insert(field_type, encoder(v));
                s
            }
            None => self,
        }
    }

    /// Add a nested TLV-encoded field
    pub fn nested<T: TlvEncode>(mut self, field_type: u64, value: &T) -> Self {
        self.stream.insert(field_type, value.tlv_encode());
        self
    }

    /// Add a vector of TLV-encoded items
    pub fn vec_field<T: TlvEncode>(mut self, field_type: u64, values: &[T]) -> Self {
        let mut buf = Vec::new();
        write_varint(&mut buf, values.len() as u64).expect("vec write cannot fail");
        for item in values {
            let encoded = item.tlv_encode();
            write_varint(&mut buf, encoded.len() as u64).expect("vec write cannot fail");
            buf.extend(encoded);
        }
        self.stream.insert(field_type, buf);
        self
    }

    /// Add a deposit_id field (16 bytes)
    pub fn deposit_id_field(mut self, field_type: u64, value: &[u8; 16]) -> Self {
        self.stream.insert(field_type, value.to_vec());
        self
    }

    /// Add a descriptor witness field (nested TLV with stack elements)
    pub fn witness_field(
        mut self,
        field_type: u64,
        witness: &crate::types::DescriptorWitness,
    ) -> Self {
        // Encode as: varint(count) || (varint(len) || element)*
        let mut buf = Vec::new();
        write_varint(&mut buf, witness.stack.len() as u64).expect("vec write cannot fail");
        for element in &witness.stack {
            write_varint(&mut buf, element.len() as u64).expect("vec write cannot fail");
            buf.extend(element);
        }
        self.stream.insert(field_type, buf);
        self
    }

    /// Build the final encoded bytes
    pub fn build(self) -> Vec<u8> {
        self.stream.encode()
    }

    /// Get the underlying TLV stream
    pub fn into_stream(self) -> TlvStream {
        self.stream
    }
}

// ============================================================================
// TLV Reader (helper for decoding)
// ============================================================================

/// Helper for reading fields from a TLV stream
pub struct TlvReader {
    stream: TlvStream,
}

impl TlvReader {
    /// Create a reader from encoded bytes
    pub fn new(data: &[u8]) -> TlvResult<Self> {
        Ok(Self {
            stream: TlvStream::decode(data)?,
        })
    }

    /// Read a required u8 field
    pub fn read_u8(&self, field_type: u64) -> TlvResult<u8> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_u8(data)
    }

    /// Read a required u16 field
    pub fn read_u16(&self, field_type: u64) -> TlvResult<u16> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_u16(data)
    }

    /// Read a required u32 field
    pub fn read_u32(&self, field_type: u64) -> TlvResult<u32> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_u32(data)
    }

    /// Read a required u64 field
    pub fn read_u64(&self, field_type: u64) -> TlvResult<u64> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_u64(data)
    }

    /// Read a required string field
    pub fn read_string(&self, field_type: u64) -> TlvResult<String> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_string(data)
    }

    /// Read a required bytes field
    pub fn read_bytes<const N: usize>(&self, field_type: u64) -> TlvResult<[u8; N]> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_bytes(data)
    }

    /// Read a required pubkey field
    pub fn read_pubkey(&self, field_type: u64) -> TlvResult<bitcoin::secp256k1::PublicKey> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_pubkey(data)
    }

    /// Read a required signature field
    pub fn read_signature(
        &self,
        field_type: u64,
    ) -> TlvResult<bitcoin::secp256k1::ecdsa::Signature> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        decode_signature(data)
    }

    /// Read an optional u64 field
    pub fn read_u64_opt(&self, field_type: u64) -> TlvResult<Option<u64>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_u64(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional u32 field
    pub fn read_u32_opt(&self, field_type: u64) -> TlvResult<Option<u32>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_u32(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional u16 field
    pub fn read_u16_opt(&self, field_type: u64) -> TlvResult<Option<u16>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_u16(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional string field
    pub fn read_string_opt(&self, field_type: u64) -> TlvResult<Option<String>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_string(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional bytes field
    pub fn read_bytes_opt<const N: usize>(&self, field_type: u64) -> TlvResult<Option<[u8; N]>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_bytes(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional pubkey field
    pub fn read_pubkey_opt(
        &self,
        field_type: u64,
    ) -> TlvResult<Option<bitcoin::secp256k1::PublicKey>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_pubkey(data)?)),
            None => Ok(None),
        }
    }

    /// Read an optional signature field
    pub fn read_signature_opt(
        &self,
        field_type: u64,
    ) -> TlvResult<Option<bitcoin::secp256k1::ecdsa::Signature>> {
        match self.stream.get(field_type) {
            Some(data) => Ok(Some(decode_signature(data)?)),
            None => Ok(None),
        }
    }

    /// Read raw bytes for a field (for nested decoding)
    pub fn read_raw(&self, field_type: u64) -> TlvResult<&[u8]> {
        self.stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })
    }

    /// Read optional raw bytes for a field
    pub fn read_raw_opt(&self, field_type: u64) -> Option<&[u8]> {
        self.stream.get(field_type)
    }

    /// Read a nested TLV-encoded field
    pub fn read_nested<T: TlvDecode>(&self, field_type: u64) -> TlvResult<T> {
        let data = self.read_raw(field_type)?;
        T::tlv_decode(data)
    }

    /// Read an optional nested TLV-encoded field
    pub fn read_nested_opt<T: TlvDecode>(&self, field_type: u64) -> TlvResult<Option<T>> {
        match self.read_raw_opt(field_type) {
            Some(data) => Ok(Some(T::tlv_decode(data)?)),
            None => Ok(None),
        }
    }

    /// Read a vector of TLV-encoded items
    pub fn read_vec<T: TlvDecode>(&self, field_type: u64) -> TlvResult<Vec<T>> {
        let data = self.read_raw(field_type)?;
        let mut cursor = Cursor::new(data);
        let count = read_varint(&mut cursor)? as usize;

        // Sanity check to prevent capacity overflow
        const MAX_VEC_COUNT: usize = 1_000_000;
        if count > MAX_VEC_COUNT {
            return Err(TlvError::InvalidFieldValue {
                field_type,
                reason: format!("vector count {} exceeds maximum {}", count, MAX_VEC_COUNT),
            });
        }

        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_varint(&mut cursor)? as usize;

            // Sanity check item length
            const MAX_ITEM_LENGTH: usize = 16 * 1024 * 1024;
            if len > MAX_ITEM_LENGTH {
                return Err(TlvError::InvalidFieldValue {
                    field_type,
                    reason: format!(
                        "vector item length {} exceeds maximum {}",
                        len, MAX_ITEM_LENGTH
                    ),
                });
            }

            let mut item_data = vec![0u8; len];
            cursor.read_exact(&mut item_data)?;
            items.push(T::tlv_decode(&item_data)?);
        }
        Ok(items)
    }

    /// Read an optional vector of TLV-encoded items
    pub fn read_vec_opt<T: TlvDecode>(&self, field_type: u64) -> TlvResult<Option<Vec<T>>> {
        match self.read_raw_opt(field_type) {
            Some(_) => Ok(Some(self.read_vec(field_type)?)),
            None => Ok(None),
        }
    }

    /// Read a required deposit_id field (16 bytes)
    pub fn read_deposit_id(&self, field_type: u64) -> TlvResult<[u8; 16]> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;
        if data.len() != 16 {
            return Err(TlvError::InvalidFieldValue {
                field_type,
                reason: format!("expected 16 bytes for deposit_id, got {}", data.len()),
            });
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(data);
        Ok(id)
    }

    /// Read an optional deposit_id field (16 bytes)
    pub fn read_deposit_id_opt(&self, field_type: u64) -> TlvResult<Option<[u8; 16]>> {
        match self.stream.get(field_type) {
            Some(data) => {
                if data.len() != 16 {
                    return Err(TlvError::InvalidFieldValue {
                        field_type,
                        reason: format!("expected 16 bytes for deposit_id, got {}", data.len()),
                    });
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(data);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Read a required witness field
    pub fn read_witness(&self, field_type: u64) -> TlvResult<crate::types::DescriptorWitness> {
        let data = self
            .stream
            .get(field_type)
            .ok_or(TlvError::MissingRequiredField { field_type })?;

        let mut cursor = Cursor::new(data);
        let count = read_varint(&mut cursor)? as usize;

        const MAX_STACK_SIZE: usize = 1000;
        if count > MAX_STACK_SIZE {
            return Err(TlvError::InvalidFieldValue {
                field_type,
                reason: format!(
                    "witness stack size {} exceeds maximum {}",
                    count, MAX_STACK_SIZE
                ),
            });
        }

        let mut stack = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_varint(&mut cursor)? as usize;
            const MAX_ELEMENT_SIZE: usize = 520; // Bitcoin script element limit
            if len > MAX_ELEMENT_SIZE {
                return Err(TlvError::InvalidFieldValue {
                    field_type,
                    reason: format!(
                        "witness element size {} exceeds maximum {}",
                        len, MAX_ELEMENT_SIZE
                    ),
                });
            }
            let mut element = vec![0u8; len];
            cursor.read_exact(&mut element)?;
            stack.push(element);
        }

        Ok(crate::types::DescriptorWitness { stack })
    }

    /// Read an optional witness field
    pub fn read_witness_opt(
        &self,
        field_type: u64,
    ) -> TlvResult<Option<crate::types::DescriptorWitness>> {
        match self.stream.get(field_type) {
            Some(_) => Ok(Some(self.read_witness(field_type)?)),
            None => Ok(None),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffffffff,
            0x100000000,
            u64::MAX,
        ];

        for &value in &test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            let decoded = read_varint(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(value, decoded, "varint roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_tlv_stream_roundtrip() {
        let mut stream = TlvStream::new();
        stream.insert(0, encode_u64(42));
        stream.insert(2, encode_string("hello"));
        stream.insert(4, vec![1, 2, 3, 4]);

        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).unwrap();

        assert_eq!(decode_u64(decoded.get(0).unwrap()).unwrap(), 42);
        assert_eq!(decode_string(decoded.get(2).unwrap()).unwrap(), "hello");
        assert_eq!(decoded.get(4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_builder_and_reader() {
        let encoded = TlvBuilder::new()
            .u64_field(0, 12345)
            .u32_field(2, 999)
            .string_field(4, "test string")
            .bytes_field(6, &[0xde, 0xad, 0xbe, 0xef])
            .build();

        let reader = TlvReader::new(&encoded).unwrap();
        assert_eq!(reader.read_u64(0).unwrap(), 12345);
        assert_eq!(reader.read_u32(2).unwrap(), 999);
        assert_eq!(reader.read_string(4).unwrap(), "test string");
        assert_eq!(reader.read_bytes::<4>(6).unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_optional_fields() {
        let encoded = TlvBuilder::new()
            .u64_field(0, 100)
            .optional(1, &Some(42u64), |v| encode_u64(*v))
            .optional(3, &None::<u64>, |v| encode_u64(*v))
            .build();

        let reader = TlvReader::new(&encoded).unwrap();
        assert_eq!(reader.read_u64(0).unwrap(), 100);
        assert_eq!(reader.read_u64_opt(1).unwrap(), Some(42));
        assert_eq!(reader.read_u64_opt(3).unwrap(), None);
    }

    #[test]
    fn test_missing_required_field() {
        let encoded = TlvBuilder::new().u64_field(0, 100).build();

        let reader = TlvReader::new(&encoded).unwrap();
        assert!(matches!(
            reader.read_u64(2),
            Err(TlvError::MissingRequiredField { field_type: 2 })
        ));
    }

    #[test]
    fn test_canonical_order_required() {
        // Manually create non-canonical order (field 2 before field 0)
        let mut bad_data = Vec::new();
        write_varint(&mut bad_data, 2).unwrap(); // type 2
        write_varint(&mut bad_data, 8).unwrap(); // length 8
        bad_data.extend(&42u64.to_be_bytes());
        write_varint(&mut bad_data, 0).unwrap(); // type 0 (out of order!)
        write_varint(&mut bad_data, 8).unwrap();
        bad_data.extend(&100u64.to_be_bytes());

        assert!(matches!(
            TlvStream::decode(&bad_data),
            Err(TlvError::NonCanonicalOrder { field_type: 0 })
        ));
    }

    #[test]
    fn test_pubkey_encoding() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let encoded = TlvBuilder::new().pubkey_field(0, &pubkey).build();

        let reader = TlvReader::new(&encoded).unwrap();
        let decoded = reader.read_pubkey(0).unwrap();
        assert_eq!(pubkey, decoded);
    }
}
