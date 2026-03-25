// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core data types for the Bitcoin Deposits Protocol.
//!
//! These types are Lightning-implementation agnostic and use serde for serialization.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Serde Helpers
// ============================================================================

/// Serde helper for PublicKey
pub mod serde_pubkey {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a PublicKey
    pub fn serialize<S>(pubkey: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        pubkey.serialize().as_slice().serialize(serializer)
    }

    /// Deserialize a PublicKey
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        PublicKey::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for 32-byte arrays
pub mod serde_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a 32-byte array
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    /// Deserialize a 32-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected 32 bytes, got {}",
                vec.len()
            )))
        }
    }
}

/// Serde helper for 64-byte arrays
pub mod serde_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a 64-byte array
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    /// Deserialize a 64-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&vec);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                vec.len()
            )))
        }
    }
}

/// Serde helper for Option<[u8; 64]>
pub mod serde_opt_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize an optional 64-byte array
    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => bytes.as_slice().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an optional 64-byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) if vec.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&vec);
                Ok(Some(arr))
            }
            Some(vec) => Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                vec.len()
            ))),
            None => Ok(None),
        }
    }
}

/// Serde helper for HashMap<PublicKey, V> - serializes as Vec of tuples
pub mod serde_pubkey_map {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_pubkey")]
        key: PublicKey,
        value: V,
    }

    /// Serialize a HashMap<PublicKey, V>
    pub fn serialize<S, V>(map: &HashMap<PublicKey, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<PublicKey, V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<PublicKey, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}

/// Serde helper for Vec<PublicKey>
pub mod serde_pubkey_vec {
    use bitcoin::secp256k1::PublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a Vec<PublicKey>
    pub fn serialize<S>(vec: &[PublicKey], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = vec.iter().map(|pk| pk.serialize().to_vec()).collect();
        bytes.serialize(serializer)
    }

    /// Deserialize a Vec<PublicKey>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        bytes
            .into_iter()
            .map(|b| PublicKey::from_slice(&b).map_err(serde::de::Error::custom))
            .collect()
    }
}

// ============================================================================
// Deposit Identifier
// ============================================================================

/// Unique deposit identifier derived from descriptor.
/// This is the first 16 bytes of SHA256(descriptor_string).
pub type DepositId = [u8; 16];

/// Compute a DepositId from a descriptor string.
/// deposit_id = SHA256(descriptor_string)[0..16]
pub fn compute_deposit_id(descriptor: &str) -> DepositId {
    let hash = sha256::Hash::hash(descriptor.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[0..16]);
    id
}

/// Serde helper for DepositId (16-byte array)
pub mod serde_deposit_id {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a DepositId as hex string
    pub fn serialize<S>(id: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(id).serialize(serializer)
    }

    /// Deserialize a DepositId from hex string
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "Expected 16 bytes for DepositId, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serde helper for HashMap<DepositId, V> - serializes as Vec of tuples with hex keys
pub mod serde_deposit_id_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_deposit_id")]
        key: [u8; 16],
        value: V,
    }

    /// Serialize a HashMap<DepositId, V>
    pub fn serialize<S, V>(map: &HashMap<[u8; 16], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<DepositId, V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<[u8; 16], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}

/// Serde helper for HashMap<[u8; 32], V> (transfer_id maps)
pub mod serde_transfer_id_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    /// Entry for serialization
    #[derive(Serialize, Deserialize)]
    struct Entry<V> {
        #[serde(with = "super::serde_32")]
        key: [u8; 32],
        value: V,
    }

    /// Serialize a HashMap<[u8; 32], V>
    pub fn serialize<S, V>(map: &HashMap<[u8; 32], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let entries: Vec<Entry<&V>> = map
            .iter()
            .map(|(k, v)| Entry { key: *k, value: v })
            .collect();
        entries.serialize(serializer)
    }

    /// Deserialize a HashMap<[u8; 32], V>
    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<[u8; 32], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let entries: Vec<Entry<V>> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.key, e.value)).collect())
    }
}

// ============================================================================
// Descriptor Witness
// ============================================================================

/// Witness data satisfying a miniscript descriptor.
///
/// Contains a stack of elements (signatures, preimages, etc.) that together
/// satisfy the spending conditions of a descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorWitness {
    /// Stack elements (signatures, preimages, etc.)
    /// Order matches witness stack order: index 0 is bottom of stack
    pub stack: Vec<Vec<u8>>,
}

impl DescriptorWitness {
    /// Create a new empty witness
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Create a witness with a single signature (for single-key descriptors)
    pub fn from_signature(signature: &[u8; 64]) -> Self {
        Self {
            stack: vec![signature.to_vec()],
        }
    }

    /// Create a witness from multiple stack elements
    pub fn from_stack(stack: Vec<Vec<u8>>) -> Self {
        Self { stack }
    }

    /// Check if the witness is empty
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Get the number of stack elements
    pub fn len(&self) -> usize {
        self.stack.len()
    }
}

impl Default for DescriptorWitness {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Serde Default Helpers
// ============================================================================

/// Default pubkey for serde deserialization (generator point G).
/// Used when deserializing older ledgers that don't have parent_pubkey.
pub fn default_parent_pubkey() -> PublicKey {
    // Use generator point G as default pubkey (well-known, deterministic)
    let generator_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];
    PublicKey::from_slice(&generator_bytes).expect("Generator point is a valid pubkey")
}

// ============================================================================
// Fee Structure
// ============================================================================

/// Fee structure for a deposit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStructure {
    /// Fixed annual fee in msats.
    pub annualized_msats: u64,
    /// Percentage fee in basis points (0.01% = 1 bps).
    pub annualized_bps: u16,
    /// How often fees are assessed (in blocks).
    pub frequency_blocks: u32,
}

impl Default for FeeStructure {
    fn default() -> Self {
        Self {
            annualized_msats: 0,
            annualized_bps: 0,
            frequency_blocks: 2016, // ~2 weeks
        }
    }
}

impl FeeStructure {
    /// Create a new fee structure.
    pub fn new(annualized_msats: u64, annualized_bps: u16, frequency_blocks: u32) -> Self {
        Self {
            annualized_msats,
            annualized_bps,
            frequency_blocks,
        }
    }

    /// Calculate fee for a given balance and number of blocks elapsed.
    pub fn calculate_fee(&self, balance: u64, blocks_elapsed: u32) -> u64 {
        // Blocks per year (approximately)
        const BLOCKS_PER_YEAR: u64 = 52560; // 365.25 * 144

        let blocks = blocks_elapsed as u64;

        // Fixed fee portion (pro-rated for blocks elapsed)
        let fixed_fee = (self.annualized_msats * blocks) / BLOCKS_PER_YEAR;

        // Percentage fee portion (pro-rated)
        let bps_fee = (balance * self.annualized_bps as u64 * blocks) / (BLOCKS_PER_YEAR * 10000);

        fixed_fee + bps_fee
    }
}

// ============================================================================
// Transfer Fee Schedule
// ============================================================================

/// Per-transfer fee schedule for a deposit.
///
/// Unlike `FeeStructure` (which defines periodic custody fees),
/// this defines the fee charged on each transfer out of the deposit.
/// Fee = `fixed_msats` + (`amount_msats` * `rate_bps` / 10_000).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferFeeSchedule {
    /// Fixed fee per transfer in msats.
    pub fixed_msats: u64,
    /// Proportional fee in basis points (1 bps = 0.01%).
    pub rate_bps: u16,
}

impl Default for TransferFeeSchedule {
    fn default() -> Self {
        Self {
            fixed_msats: 2,
            rate_bps: 20,
        }
    }
}

impl TransferFeeSchedule {
    pub fn new(fixed_msats: u64, rate_bps: u16) -> Self {
        Self { fixed_msats, rate_bps }
    }

    /// Calculate the transfer fee for a given amount in msats.
    pub fn calculate_fee(&self, amount_msats: u64) -> u64 {
        let proportional = (amount_msats * self.rate_bps as u64) / 10_000;
        self.fixed_msats.saturating_add(proportional)
    }
}

// ============================================================================
// Invoice
// ============================================================================

/// An invoice associated with a deposit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// Unique invoice identifier.
    pub id: String,
    /// Payment hash.
    #[serde(with = "serde_32")]
    pub payment_hash: [u8; 32],
    /// Invoice amount in millisatoshis.
    pub amount: u64,
    /// Expiration timestamp (Unix timestamp).
    pub expires: u64,
    /// Which deposit this invoice is assigned to.
    #[serde(with = "serde_deposit_id")]
    pub assigned_deposit: DepositId,
    /// BOLT11 invoice string.
    pub bolt11: String,
}

impl Invoice {
    /// Check if invoice is expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires
    }
}

// ============================================================================
// Pending Invoice
// ============================================================================

/// A pending invoice awaiting cosigning or payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInvoice {
    /// Invoice amount in millisatoshis.
    pub amount: u64,
    /// Payment hash.
    #[serde(with = "serde_32")]
    pub payment_hash: [u8; 32],
    /// Expiration timestamp (Unix timestamp).
    pub expires: u64,
    /// Deposit that will receive payment.
    #[serde(with = "serde_deposit_id")]
    pub assigned_deposit: DepositId,
    /// Invoice ID.
    pub invoice_id: String,
    /// BOLT11 invoice string.
    pub bolt11: String,
}

impl PendingInvoice {
    /// Check if pending invoice is expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires
    }
}

// ============================================================================
// Pending Transfer
// ============================================================================

/// A pending conditional transfer between deposits.
///
/// Created by TransferLock, resolved by TransferComplete (funds to destination)
/// or TransferFail (funds returned to source).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTransfer {
    /// Unique transfer identifier (hash of signing message).
    #[serde(with = "serde_32")]
    pub transfer_id: [u8; 32],
    /// Nonce used to prevent collisions.
    #[serde(with = "serde_32")]
    pub nonce: [u8; 32],
    /// Source deposit that funds are locked from.
    #[serde(with = "serde_deposit_id")]
    pub source_deposit_id: DepositId,
    /// Destination deposit that will receive funds on completion.
    #[serde(with = "serde_deposit_id")]
    pub destination_deposit_id: DepositId,
    /// Amount being transferred (excluding fee).
    pub amount: u64,
    /// Fee for the custodian.
    pub fee: u64,
    /// Miniscript descriptor that must be satisfied to complete.
    /// Usually "sha256(H)" for hash-locked transfers.
    pub completion_script: String,
    /// Absolute block height after which the transfer can be timed out.
    pub timeout_height: u32,
}

impl PendingTransfer {
    /// Total locked amount (amount + fee).
    pub fn total_locked(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }
}

// ============================================================================
// Deposit
// ============================================================================

/// A user deposit in the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// Unique identifier (hash of descriptor).
    #[serde(with = "serde_deposit_id")]
    pub deposit_id: DepositId,
    /// Miniscript descriptor controlling this deposit.
    /// Examples:
    ///   "pk(02abc...)"                           - single key (current behavior)
    ///   "multi(2,pk1,pk2,pk3)"                   - 2-of-3 multisig
    ///   "and(pk(A),after(100))"                  - key + timelock
    ///   "or(pk(A),and(pk(B),sha256(H)))"         - key OR (key + hashlock)
    pub descriptor: String,
    /// Current balance in millisatoshis.
    pub balance: u64,
    /// Locked balance for pending payments (millisatoshis).
    pub locked_balance: u64,
    /// Outstanding unexpired invoices.
    pub invoices: Vec<Invoice>,
    /// Fee structure for this deposit.
    pub fees: FeeStructure,
    /// Block height of last fee assessment.
    pub last_fee_assessment: u32,
    /// Amount pledged as collateral backing for the operator (millisatoshis).
    /// This amount cannot be withdrawn until the lock expires.
    #[serde(default)]
    pub collateral_lock_amount: u64,
    /// Block height when the collateral pledge lock expires.
    /// After this block, the pledged funds can be withdrawn.
    #[serde(default)]
    pub collateral_lock_expires: u32,
    /// Per-transfer fee schedule (fixed + proportional).
    #[serde(default)]
    pub transfer_fees: TransferFeeSchedule,
    /// If true, this deposit is collateral — subject to collateral rules only.
    #[serde(default)]
    pub is_collateral: bool,
    /// If true, incoming funds require a signature from the deposit key.
    #[serde(default)]
    pub receive_requires_sig: bool,
    /// Blocks after deposit creation before fees can be changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_change_after_blocks: Option<u32>,
    /// Blocks of notice required before a fee change takes effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_change_notice_blocks: Option<u32>,
    /// Maximum fee change per adjustment in bps of current fee (default 1000 = 10%).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_change_limit_bps: Option<u16>,
    /// Block height at which the deposit was opened (for fee_change_after_blocks).
    #[serde(default)]
    pub opened_at_block: u32,
    /// Pending fee change: new fees and the block at which they take effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_fee_change: Option<(FeeStructure, u32)>,
}

impl Deposit {
    /// Create a new deposit with a miniscript descriptor.
    ///
    /// The deposit_id is automatically computed from the descriptor.
    pub fn new(descriptor: String, fees: Option<FeeStructure>) -> Self {
        let deposit_id = compute_deposit_id(&descriptor);
        Self {
            deposit_id,
            descriptor,
            balance: 0,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: fees.unwrap_or_default(),
            last_fee_assessment: 0,
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(),
            is_collateral: false,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            opened_at_block: 0,
            pending_fee_change: None,
        }
    }

    /// Create a new deposit from a single public key.
    ///
    /// This is a convenience method that creates a pk() descriptor.
    pub fn from_pubkey(pubkey: &PublicKey, fees: Option<FeeStructure>) -> Self {
        let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
        Self::new(descriptor, fees)
    }

    /// Get the deposit_id as a hex string
    pub fn deposit_id_hex(&self) -> String {
        hex::encode(self.deposit_id)
    }

    /// Get available (unlocked) balance.
    pub fn available_balance(&self) -> u64 {
        self.balance.saturating_sub(self.locked_balance)
    }

    /// Credit the deposit with a payment.
    pub fn credit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Debit the deposit.
    pub fn debit(&mut self, amount: u64) -> Result<(), crate::DepositsError> {
        if self.available_balance() < amount {
            return Err(crate::DepositsError::InsufficientDepositBalance {
                available: self.available_balance(),
                required: amount,
            });
        }
        self.balance = self.balance.saturating_sub(amount);
        Ok(())
    }

    /// Lock funds for a pending payment.
    pub fn lock(&mut self, amount: u64) -> Result<(), crate::DepositsError> {
        if self.available_balance() < amount {
            return Err(crate::DepositsError::InsufficientDepositBalance {
                available: self.available_balance(),
                required: amount,
            });
        }
        self.locked_balance = self.locked_balance.saturating_add(amount);
        Ok(())
    }

    /// Unlock funds from a failed payment.
    pub fn unlock(&mut self, amount: u64) {
        self.locked_balance = self.locked_balance.saturating_sub(amount);
    }

    /// Fulfill a locked payment (debit the locked funds).
    pub fn fulfill(&mut self, amount: u64) {
        self.locked_balance = self.locked_balance.saturating_sub(amount);
        self.balance = self.balance.saturating_sub(amount);
    }

    /// Calculate fees due since last assessment.
    pub fn calculate_fees_due(&self, current_block: u32) -> u64 {
        if current_block <= self.last_fee_assessment {
            return 0;
        }
        let blocks_elapsed = current_block - self.last_fee_assessment;
        if blocks_elapsed < self.fees.frequency_blocks {
            return 0;
        }
        self.fees.calculate_fee(self.balance, blocks_elapsed)
    }

    /// Collect fees and update last assessment block.
    pub fn collect_fees(&mut self, current_block: u32) -> u64 {
        let fee = self.calculate_fees_due(current_block);
        if fee > 0 && fee <= self.balance {
            self.balance = self.balance.saturating_sub(fee);
            self.last_fee_assessment = current_block;
        }
        fee
    }
}

// ============================================================================
// Reserves Output
// ============================================================================

/// Reserves output backing deposits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservesOutput {
    /// Associated channel ID.
    #[serde(with = "serde_32")]
    pub channel_id: [u8; 32],
    /// Amount held in reserves (millisatoshis).
    pub amount: u64,
    /// Public key that can spend reserves after timelock.
    #[serde(with = "serde_pubkey")]
    pub spend_to: PublicKey,
}

impl ReservesOutput {
    /// Create a new reserves output.
    pub fn new(channel_id: [u8; 32], amount: u64, spend_to: PublicKey) -> Self {
        Self {
            channel_id,
            amount,
            spend_to,
        }
    }
}

impl Default for ReservesOutput {
    fn default() -> Self {
        // Use generator point G as default pubkey (well-known, deterministic)
        let generator_bytes = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
            0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
            0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        Self {
            channel_id: [0u8; 32],
            amount: 0,
            spend_to: PublicKey::from_slice(&generator_bytes)
                .expect("Generator point is a valid pubkey"),
        }
    }
}

// ============================================================================
// Collateral Attestation
// ============================================================================

/// A record of joining another operator's quorum as a monitoring member.
///
/// When a node agrees to be a quorum member for another operator (via CollateralConsentResponse),
/// this record is added to the consenting node's own ledger. This creates a two-sided
/// auditable trail:
/// - The operator's ledger has: QuorumAddMember { quorum_member, signature }
/// - The quorum member's ledger has: QuorumJoin { operator_id, ledger_id, signature }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumMembership {
    /// The operator whose quorum we joined.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// The ledger_id (64-char hex hash) of the ledger we're monitoring.
    pub ledger_id: String,
    /// Block height when our membership commitment expires.
    /// After this block, we are no longer obligated to monitor this ledger.
    pub membership_expires: u32,
    /// Our consent signature (matches quorum_member_signature in QuorumAddMember).
    #[serde(with = "serde_64")]
    pub our_signature: [u8; 64],
    /// Sequence number when we joined (for audit trail).
    pub joined_at_sequence: u64,
}

/// A quorum member with their associated ledger for collateral binding.
///
/// When adding a quorum member, we explicitly record which ledger they will
/// use to provide collateral backing. This creates a verifiable link between
/// the quorum membership and the collateral source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumMember {
    /// The quorum member's public key.
    #[serde(with = "serde_pubkey")]
    pub pubkey: PublicKey,
    /// The ledger ID where this member will lock collateral.
    /// This must match the collateral_ledger_id in any CollateralAttestation from this member.
    pub ledger_id: String,
    /// Minimum annualized fee rate (basis points) this member requires.
    /// DepositOpen fees below this should be rejected during co-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_fee_bps: Option<u16>,
    /// Minimum annualized fixed fee (msats/year) this member requires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_fee_fixed: Option<u64>,
    /// Maximum fee collection period (blocks) this member allows.
    /// Longer periods mean less frequent fee collection (worse for the member).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_period: Option<u32>,
    /// Minimum collateral (msats) the member commits to maintain.
    /// Obligations are limited to 2x the smallest member's commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_lock_amount: Option<u64>,
    /// Block height until which the member's collateral must remain locked.
    /// Membership duration is limited to the shortest lock time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_lock_until: Option<u32>,
    /// Blocks before a member must respond to embedded fraud evidence (default 144 ~1 day)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_response_blocks: Option<u32>,
    /// Blocks after DisputeEnter during which members must arm for lottery (default 144 ~1 day)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_arm_blocks: Option<u32>,
    /// Blocks before unprocessed signed request becomes provable censorship (default 72 ~12hrs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_response_blocks: Option<u32>,
    /// Maximum timeout_height distance for TransferLock (default 1008 ~1 week)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_timeout_blocks: Option<u32>,
    /// Maximum serialized descriptor size (bytes) member will accept on deposits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_descriptor_bytes: Option<u32>,
}

/// A collateral attestation from a quorum member proving their reserves backing.
///
/// Partners periodically sign attestations proving they have committed
/// collateral in their channels backing this ledger's deposits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralAttestation {
    /// Operator node ID this attestation is for.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Partner who signed this attestation.
    #[serde(with = "serde_pubkey")]
    pub quorum_member: PublicKey,
    /// The ledger ID where collateral is locked.
    /// Must match member_ledger_id from the QuorumAddMember that added this member.
    #[serde(default)]
    pub collateral_ledger_id: String,
    /// Amount of collateral committed (satoshis).
    pub amount: u64,
    /// Block height when this attestation was created.
    pub block_height: u32,
    /// Block height when the collateral lock expires.
    #[serde(default)]
    pub lock_until_block: u32,
    /// Signature over the attestation content.
    #[serde(with = "serde_64")]
    pub signature: [u8; 64],
    /// Hash of the partner's ledger state when they created this attestation.
    #[serde(with = "serde_32")]
    pub ledger_hash: [u8; 32],
}

impl CollateralAttestation {
    /// Create a new collateral attestation.
    pub fn new(
        operator_id: PublicKey,
        quorum_member: PublicKey,
        collateral_ledger_id: String,
        amount: u64,
        block_height: u32,
        lock_until_block: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    ) -> Self {
        Self {
            operator_id,
            quorum_member,
            collateral_ledger_id,
            amount,
            block_height,
            lock_until_block,
            signature,
            ledger_hash,
        }
    }

    /// Get the available collateral from this attestation.
    pub fn available_collateral(&self) -> u64 {
        self.amount
    }

    /// Check if this attestation is recent enough.
    pub fn is_recent(&self, current_block: u32, max_age_blocks: u32) -> bool {
        current_block.saturating_sub(self.block_height) <= max_age_blocks
    }
}

// ============================================================================
// Dispute State
// ============================================================================

/// State of a ledger with respect to custody disputes.
///
/// A ledger's dispute state follows this state machine:
/// ```text
/// NORMAL
///   │
///   │ DisputeEnter (from quorum member)
///   ▼
/// DISPUTED
///   │  - Quorum is disbanded
///   │  - All collateral attestations voided
///   │  - Only QuorumAddMember and CollateralAttestation allowed
///   │
///   │ DisputeArmed (pre-commitment)
///   ▼
/// ARMED
///   │  - No more quorum/collateral changes
///   │  - Candidate is locked in for entropy selection
///   │  - Only DisputeAcquire or DisputeYield allowed
///   │
///   ├─── DisputeAcquire ──► NORMAL (new operator, reserves spent)
///   │
///   └─── DisputeYield ───► TOMBSTONED (branch terminated)
/// ```
/// Quorum lifecycle state machine.
///
/// ```text
/// PreQuorum
///   │  - Only is_collateral deposits allowed
///   │  - Operator-only signatures (no co-signing)
///   │  - QuorumAddMember populates pending member list
///   │
///   │ QuorumBegin (reserves rotation to Taproot)
///   ▼
/// Active
///   │  - Co-signatures required for all updates
///   │  - Full deposit operations allowed
///   │  - Must re-rotate before quorum_expiry
///   │
///   ├─── QuorumBegin ──► Active (re-rotation, expiry extended)
///   │
///   └─── expiry passes ──► Expired (non-conforming, ledger reassigned)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QuorumState {
    /// No quorum yet. Only collateral deposits allowed, operator-only signatures.
    #[default]
    PreQuorum,
    /// Quorum is active. Co-signatures required, full operations allowed.
    Active,
    /// Quorum expired without re-rotation. Chain is non-conforming.
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DisputeState {
    /// Normal operation - no active dispute
    #[default]
    Normal,
    /// Dispute has been opened. Quorum is disbanded, only QuorumAddMember
    /// and CollateralAttestation operations are allowed.
    Disputed,
    /// Candidate is armed and locked in for entropy selection.
    /// No more quorum/collateral changes allowed.
    Armed,
    /// Branch has been terminated (lost entropy selection or yielded).
    /// No further updates allowed.
    Tombstoned,
}

impl DisputeState {
    /// Check if operations can be appended in this state.
    pub fn allows_operations(&self) -> bool {
        !matches!(self, DisputeState::Tombstoned)
    }

    /// Check if this state allows the given operation type.
    ///
    /// Returns true if the operation is valid for this state, false otherwise.
    pub fn allows_operation(&self, operation_discriminant: u8) -> bool {
        match self {
            DisputeState::Normal => {
                // Normal state allows all operations except DisputeArmed, DisputeAcquire, DisputeYield
                // DisputeEnter is the only way to transition out
                !matches!(operation_discriminant, 57 | 55 | 56) // DisputeArmed, DisputeAcquire, DisputeYield
            }
            DisputeState::Disputed => {
                // Only QuorumAddMember, CollateralAttestation, and DisputeArmed allowed
                matches!(operation_discriminant, 43 | 42 | 57) // QuorumAddMember, CollateralAttestation, DisputeArmed
            }
            DisputeState::Armed => {
                // Only DisputeAcquire or DisputeYield allowed
                matches!(operation_discriminant, 55 | 56) // DisputeAcquire, DisputeYield
            }
            DisputeState::Tombstoned => {
                // No operations allowed
                false
            }
        }
    }
}

/// Compute the entropy selection score for a candidate.
///
/// The score is computed as: SHA256(entropy_block_hash || candidate_pubkey)
/// Lower scores win (sorted ascending).
pub fn entropy_selection_score(entropy_block_hash: &[u8; 32], candidate: &PublicKey) -> [u8; 32] {
    use bitcoin::hashes::{Hash, sha256};

    let mut input = Vec::with_capacity(32 + 33);
    input.extend_from_slice(entropy_block_hash);
    input.extend_from_slice(&candidate.serialize());
    *sha256::Hash::hash(&input).as_byte_array()
}

/// Select the winner from a list of candidates using entropy-based selection.
///
/// Per the dispute protocol, the winner is determined by:
/// `winner = candidates.sort_by(|c| hash(entropy_block_hash || c.pubkey)).first()`
///
/// This ensures:
/// - No one can predict the winner before the entropy block
/// - Everyone can verify the winner after the entropy block
/// - The selection is deterministic
///
/// Returns None if candidates is empty.
pub fn select_entropy_winner(
    entropy_block_hash: &[u8; 32],
    candidates: &[PublicKey],
) -> Option<PublicKey> {
    if candidates.is_empty() {
        return None;
    }

    candidates
        .iter()
        .min_by_key(|c| entropy_selection_score(entropy_block_hash, c))
        .copied()
}

/// Check if a candidate is the entropy-selected winner.
///
/// Returns true if this candidate has the lowest score among all candidates.
pub fn is_entropy_winner(
    entropy_block_hash: &[u8; 32],
    candidate: &PublicKey,
    all_candidates: &[PublicKey],
) -> bool {
    select_entropy_winner(entropy_block_hash, all_candidates)
        .map(|winner| &winner == candidate)
        .unwrap_or(false)
}

// ============================================================================
// Ledger State
// ============================================================================

/// Complete state of a Bitcoin Deposits ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    /// Unique ledger identifier (hash of operator + reserves + genesis_block).
    /// This is fixed at genesis and survives operator changes during recovery.
    #[serde(with = "serde_32")]
    pub ledger_id: [u8; 32],
    /// Block height when this ledger was opened.
    /// Used in ledger_id computation and for historical reference.
    pub genesis_block: u32,
    /// Operator's public key.
    #[serde(with = "serde_pubkey")]
    pub operator_key: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_key: String,
    /// Reserves outpoint ("txid:vout") that backs this ledger.
    /// Used to distinguish reserves when multiple share the same P2WSH address.
    #[serde(default)]
    pub reserves_outpoint: Option<String>,
    /// All deposits in this ledger, keyed by deposit_id.
    #[serde(with = "serde_deposit_id_map")]
    pub deposits: HashMap<DepositId, Deposit>,
    /// Current reserves output.
    pub reserves: ReservesOutput,
    /// Pending invoice awaiting payment.
    pub pending_invoice: Option<PendingInvoice>,
    /// Quorum lifecycle state (PreQuorum → Active → Expired).
    /// Determines co-signature requirements and allowed operation types.
    #[serde(default)]
    pub quorum_state: QuorumState,
    /// Active quorum members (confirmed by QuorumBegin).
    /// These are the members whose co-signatures are required for operations.
    #[serde(default)]
    pub quorum_members: Vec<QuorumMember>,
    /// Pending quorum members (added by QuorumAddMember, awaiting QuorumBegin).
    /// Promoted to quorum_members when the next QuorumBegin is applied.
    #[serde(default)]
    pub pending_quorum_members: Vec<QuorumMember>,
    /// Committed collateral amount (our collateral pledged to others).
    pub collateral_amount: u64,
    /// Block height of last collateral increase.
    /// Used to enforce the constraint that decreases can't happen within
    /// COLLATERAL_REPORTING_PERIOD_BLOCKS of an increase.
    #[serde(default)]
    pub last_collateral_increase_block: Option<u32>,
    /// Block height at which collateral size requirements are enforced.
    ///
    /// Before this block:
    /// - Ledger conformance is always enforced (valid signatures, state roots)
    /// - Partner validation is always required
    /// Collateral received from other operators that backs this ledger's deposits.
    /// In the 100%+100% model, deposits need 100% reserves + 100% received collateral.
    #[serde(default)]
    pub received_collateral_amount: u64,
    /// Total attested collateral from QuorumBegin (msats).
    /// Used for obligation limit: obligations <= min(reserves, total_collateral, 2*min_member_collateral).
    #[serde(default)]
    pub total_collateral: u64,
    /// Block height when the current quorum expires (from QuorumBegin).
    #[serde(default)]
    pub quorum_expiry: Option<u32>,
    /// Collateral attestations from quorum members proving their reserves.
    /// Key is the partner's public key (must be in quorum_members list).
    /// Attestations are updated periodically and validated before use.
    #[serde(with = "serde_pubkey_map", default)]
    pub collateral_attestations: HashMap<PublicKey, CollateralAttestation>,
    /// Partner's deepest acknowledged hash.
    /// This is the most recent ledger hash that our channel partner has sent an ACK for.
    /// When partner ACKs a message, we update this to the new_hash from that message.
    /// Starts at [0; 32] for new ledgers, updated as partner ACKs our messages.
    #[serde(with = "serde_32", default)]
    pub partner_deepest_ack_hash: [u8; 32],
    /// Channel's deepest embedded commitment hash.
    /// This is the most recent ledger hash that has been embedded in a Lightning
    /// commitment transaction's reserves output.
    /// Updated when we successfully update the channel commitment with new reserves.
    /// Starts at [0; 32] for new ledgers, updated when commitments include new state.
    #[serde(with = "serde_32", default)]
    pub channel_deepest_commitment_hash: [u8; 32],
    /// Last update timestamp (Unix timestamp).
    #[serde(default)]
    pub last_updated: u64,
    /// Pending out-of-order updates waiting for earlier updates to arrive.
    /// Key is the sequence number of the pending update.
    /// When an update arrives that fills a gap, we flush all consecutive pending updates.
    #[serde(default)]
    pub pending_updates: HashMap<u64, SignedLedgerUpdate>,
    /// Pending conditional transfers between deposits.
    /// Key is the transfer_id (hash of the signing message).
    #[serde(with = "serde_transfer_id_map", default)]
    pub pending_transfers: HashMap<[u8; 32], PendingTransfer>,
    /// Current sequence number.
    pub sequence: u64,
    /// Current ledger hash.
    #[serde(with = "serde_32")]
    pub hash: [u8; 32],
    /// Quorums we have joined as a monitoring member.
    /// Records our commitment to monitor other operators' ledgers.
    #[serde(default)]
    pub joined_quorums: Vec<QuorumMembership>,
    // ========================================================================
    // Dispute State
    // ========================================================================
    /// Current dispute state of the ledger.
    /// Determines which operations are allowed and signature requirements.
    #[serde(default)]
    pub dispute_state: DisputeState,
    /// The pubkey that signed the last update.
    /// All subsequent updates must be signed by this same pubkey (except DisputeEnter).
    /// For Normal state this is typically the operator; for Disputed/Ready it's the dispute opener.
    #[serde(with = "serde_pubkey", default = "default_parent_pubkey")]
    pub parent_pubkey: PublicKey,
    /// Quorum members at the point of the last DisputeEnter.
    /// Used to verify that DisputeEnter signers were actually quorum members at the fork point.
    /// Only populated when dispute_state != Normal.
    #[serde(default)]
    pub quorum_at_fork: Vec<QuorumMember>,
    /// Sequence number of the last valid update before the dispute.
    /// Used for dispute validation.
    #[serde(default)]
    pub dispute_fork_sequence: u64,
}

impl LedgerState {
    /// Compute a ledger_id from its genesis parameters.
    ///
    /// The ledger_id is SHA256(operator_key || reserves_key || genesis_block).
    /// This is fixed at genesis and survives operator changes during recovery.
    pub fn compute_ledger_id(operator_key: &PublicKey, reserves_key: &str, genesis_block: u32) -> [u8; 32] {
        use bitcoin::hashes::{Hash, sha256};
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&operator_key.serialize());
        preimage.extend_from_slice(reserves_key.as_bytes());
        preimage.extend_from_slice(&genesis_block.to_le_bytes());
        sha256::Hash::hash(&preimage).to_byte_array()
    }

    /// Create a new empty ledger state.
    pub fn new(operator_key: PublicKey, reserves_key: String, genesis_block: u32) -> Self {
        let ledger_id = Self::compute_ledger_id(&operator_key, &reserves_key, genesis_block);
        Self {
            ledger_id,
            genesis_block,
            operator_key,
            reserves_key,
            reserves_outpoint: None,
            deposits: HashMap::new(),
            reserves: ReservesOutput::default(),
            pending_invoice: None,
            quorum_state: QuorumState::PreQuorum,
            quorum_members: Vec::new(),
            pending_quorum_members: Vec::new(),
            collateral_amount: 0,
            last_collateral_increase_block: None,
            received_collateral_amount: 0,
            total_collateral: 0,
            quorum_expiry: None,
            collateral_attestations: HashMap::new(),
            partner_deepest_ack_hash: [0u8; 32],
            channel_deepest_commitment_hash: [0u8; 32],
            last_updated: 0,
            pending_updates: HashMap::new(),
            pending_transfers: HashMap::new(),
            sequence: 0,
            hash: [0u8; 32],
            joined_quorums: Vec::new(),
            // Dispute state - start in Normal
            dispute_state: DisputeState::Normal,
            parent_pubkey: operator_key, // Initially operator signs everything
            quorum_at_fork: Vec::new(),
            dispute_fork_sequence: 0,
        }
    }

    /// Get the ledger_id as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    /// Get total balance across all deposits (millisatoshis).
    pub fn total_deposit_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.balance).sum()
    }

    /// Get total balance of collateral deposits held by other operators on this ledger (msats).
    pub fn total_held_collateral(&self) -> u64 {
        self.deposits.values().filter(|d| d.is_collateral).map(|d| d.balance).sum()
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.locked_balance).sum()
    }

    /// Get reserves amount (millisatoshis).
    pub fn reserves_amount(&self) -> u64 {
        self.reserves.amount
    }

    /// Check if reserves are sufficient.
    pub fn has_sufficient_reserves(&self) -> bool {
        // Both reserves and deposits are in millisatoshis
        self.reserves_amount() >= self.total_deposit_balance()
    }

    // ========================================================================
    // Collateral Tracking Methods
    // ========================================================================

    /// Update or add a collateral attestation from a quorum member.
    ///
    /// Returns error if the partner is not in the quorum_members list.
    pub fn update_collateral_attestation(
        &mut self,
        partner: PublicKey,
        attestation: CollateralAttestation,
    ) -> Result<(), crate::DepositsError> {
        if !self.quorum_members.iter().any(|m| m.pubkey == partner) {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "invalid_quorum_member".to_string(),
                details: format!("Partner {} is not a quorum member for this ledger", partner),
            });
        }
        self.collateral_attestations.insert(partner, attestation);
        Ok(())
    }

    /// Get the total available collateral from all attestations.
    ///
    /// Only counts attestations that are recent enough (within max_age_blocks of current_block).
    pub fn total_available_collateral(&self, current_block: u32, max_age_blocks: u32) -> u64 {
        self.collateral_attestations
            .values()
            .filter(|a| a.is_recent(current_block, max_age_blocks))
            .map(|a| a.available_collateral())
            .sum()
    }

    /// Get available collateral from a specific quorum member.
    pub fn partner_available_collateral(&self, partner: &PublicKey) -> Option<u64> {
        self.collateral_attestations
            .get(partner)
            .map(|a| a.available_collateral())
    }

    /// Check if all quorum members have valid attestations.
    ///
    /// Returns list of partners missing attestations or with stale attestations.
    pub fn missing_attestations(&self, current_block: u32, max_age_blocks: u32) -> Vec<PublicKey> {
        self.quorum_members
            .iter()
            .filter(|member| {
                match self.collateral_attestations.get(&member.pubkey) {
                    None => true,
                    Some(a) => !a.is_recent(current_block, max_age_blocks),
                }
            })
            .map(|m| m.pubkey)
            .collect()
    }

    /// Clear all collateral attestations.
    pub fn clear_collateral_attestations(&mut self) {
        self.collateral_attestations.clear();
    }

    // ========================================================================
    // ACK/Commitment Hash Tracking Methods
    // ========================================================================

    /// Update the partner's deepest acknowledged hash.
    ///
    /// Called when partner sends an ACK for one of our messages.
    /// The new_hash should be the current_hash from the ACKed message.
    pub fn update_partner_ack_hash(&mut self, new_hash: [u8; 32]) {
        self.partner_deepest_ack_hash = new_hash;
    }

    /// Update the channel's deepest commitment hash.
    ///
    /// Called when the Lightning channel commitment transaction is updated
    /// to include a new reserves output with this ledger state.
    pub fn update_commitment_hash(&mut self, new_hash: [u8; 32]) {
        self.channel_deepest_commitment_hash = new_hash;
    }

    /// Update the last_updated timestamp.
    pub fn touch(&mut self, timestamp: u64) {
        self.last_updated = timestamp;
    }

    /// Check if partner has acknowledged the current ledger state.
    ///
    /// Returns true if partner_deepest_ack_hash matches the current hash.
    pub fn is_fully_acked(&self) -> bool {
        self.partner_deepest_ack_hash == self.hash
    }

    /// Check if the commitment includes the current ledger state.
    ///
    /// Returns true if channel_deepest_commitment_hash matches the current hash.
    pub fn is_fully_committed(&self) -> bool {
        self.channel_deepest_commitment_hash == self.hash
    }

    /// Get the number of updates since partner's last ACK.
    ///
    /// Returns None if we can't determine this (e.g., hashes don't match known states).
    /// This requires knowing the sequence numbers, which we have in the hash field
    /// but would need the full history to map hash->sequence.
    /// For now, we just check if they match.
    pub fn updates_since_ack(&self) -> u64 {
        if self.is_fully_acked() {
            0
        } else {
            // We don't have sequence tracking for partner_deepest_ack_hash
            // This would need to be enhanced if we want precise counts
            1 // Return 1 to indicate "at least one" unacked update
        }
    }

    // ========================================================================
    // Pending Updates Queue Methods
    // ========================================================================

    /// Queue an out-of-order update for later processing.
    ///
    /// Called when an update arrives with a sequence number higher than expected.
    /// The update is stored until the gap is filled.
    pub fn queue_pending_update(&mut self, update: SignedLedgerUpdate) {
        self.pending_updates.insert(update.sequence_number, update);
    }

    /// Get the number of pending (out-of-order) updates.
    pub fn pending_update_count(&self) -> usize {
        self.pending_updates.len()
    }

    /// Check if there are any pending updates.
    pub fn has_pending_updates(&self) -> bool {
        !self.pending_updates.is_empty()
    }

    /// Get a pending update by sequence number.
    pub fn get_pending_update(&self, sequence: u64) -> Option<&SignedLedgerUpdate> {
        self.pending_updates.get(&sequence)
    }

    /// Remove and return a pending update by sequence number.
    pub fn take_pending_update(&mut self, sequence: u64) -> Option<SignedLedgerUpdate> {
        self.pending_updates.remove(&sequence)
    }

    /// Get all pending update sequence numbers, sorted.
    pub fn pending_sequences(&self) -> Vec<u64> {
        let mut seqs: Vec<u64> = self.pending_updates.keys().copied().collect();
        seqs.sort();
        seqs
    }

    /// Clear all pending updates.
    pub fn clear_pending_updates(&mut self) {
        self.pending_updates.clear();
    }

    /// Check if the next expected sequence has a pending update.
    ///
    /// The next expected sequence is current sequence + 1.
    pub fn has_next_pending(&self) -> bool {
        self.pending_updates.contains_key(&(self.sequence + 1))
    }

    /// Get active quorum memberships (not expired).
    ///
    /// Returns references to memberships where `membership_expires > current_block`.
    pub fn active_quorum_memberships(&self, current_block: u32) -> Vec<&QuorumMembership> {
        self.joined_quorums.iter()
            .filter(|m| m.membership_expires > current_block)
            .collect()
    }
}

// ============================================================================
// Signed Ledger Update
// ============================================================================

/// A signed update to the ledger state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerUpdate {
    /// The ledger operation (serialized DepositsMessage).
    pub message: Vec<u8>,
    /// Type of the message (for quick filtering without deserializing).
    pub message_type: u16,
    /// Operator's public key (for signature verification).
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Unique ledger identifier: SHA256(genesis_operator || reserves_id || genesis_block).
    #[serde(with = "serde_32")]
    pub ledger_id: [u8; 32],
    /// Deterministic sequence number (starts at 0 for LedgerOpened).
    pub sequence_number: u64,
    /// Hash of previous ledger state (creates cryptographic chain).
    #[serde(with = "serde_32")]
    pub previous_hash: [u8; 32],
    /// Hash of current ledger state after this update.
    #[serde(with = "serde_32")]
    pub current_hash: [u8; 32],
    /// Block height when this update was created.
    #[serde(default)]
    pub block_height: u32,
    /// Block hash at the time this update was created.
    #[serde(default, with = "serde_32")]
    pub block_hash: [u8; 32],
    /// Co-signer's signature over update content.
    #[serde(with = "serde_64")]
    pub cosign_signature: [u8; 64],
    /// Operator's final signature covering co-signer's signature.
    #[serde(with = "serde_64")]
    pub operator_signature: [u8; 64],
    /// Public key of the quorum member who co-signed this update (if co-signed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosigner_pubkey: Option<PublicKey>,
    /// Current hash of the cosigner's own ledger at time of co-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_ledger_hash: Option<[u8; 32]>,
}

impl SignedLedgerUpdate {
    /// Compute current_hash: commits to content, causal ordering, and co-signature.
    ///
    /// `SHA256(sequence || previous_hash || message [|| member_ledger_hash] [|| cosign_signature])`
    ///
    /// The operator signs current_hash. The operator's signature is not in
    /// current_hash (circular), but is folded into the chain via chain_hash().
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.sequence_number.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(&self.message);
        if let Some(ref mlh) = self.member_ledger_hash {
            hasher.update(mlh);
        }
        if self.cosign_signature != [0u8; 64] {
            hasher.update(&self.cosign_signature);
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute the chain hash: the value used as previous_hash for the next update.
    ///
    /// `SHA256(current_hash || operator_signature)`
    ///
    /// This folds the operator's signature into the chain without circularity.
    /// The next update's previous_hash = this update's chain_hash().
    pub fn chain_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.current_hash);
        hasher.update(&self.operator_signature);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify current_hash matches the computed value.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.current_hash
    }

    /// Get the ledger ID as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    // ========================================================================
    // Signature Methods
    // ========================================================================

    /// Compute the data that the co-signer signs (update content only, no operator signature).
    ///
    /// Co-signer signs: message || message_type || sequence || prev_hash
    /// Does NOT include current_hash — the hash is finalized after co-signing
    /// (it incorporates member_ledger_hash for causal ordering).
    /// Co-signer signs ONLY the content, NOT any operator signature.
    /// This prevents operator from tricking co-signer into endorsing invalid state.
    pub fn cosign_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.message);
        data.extend_from_slice(&self.message_type.to_le_bytes());
        data.extend_from_slice(&self.sequence_number.to_le_bytes());
        data.extend_from_slice(&self.previous_hash);
        data
    }

    /// Compute the data that the operator signs (content + co-signer's signature).
    ///
    /// Operator signs: cosign_data || cosign_signature
    /// This seals the bilateral agreement and proves operator accepted co-signer's validation.
    pub fn operator_signing_data(&self) -> Vec<u8> {
        let mut data = self.cosign_data();
        data.extend_from_slice(&self.cosign_signature);
        data
    }

    /// Verify the co-signer's signature over the update content.
    ///
    /// The co-signer uses BIP-340 tagged hashing:
    /// `SHA256(SHA256("deposits/cosign") || SHA256("deposits/cosign") || cosign_data || member_ledger_hash)`
    ///
    /// The co-signer pubkey must be provided by the caller (from the Ledger).
    /// For BDK ledgers without a co-signer, pass None and this returns Ok.
    pub fn verify_cosign_signature(&self, partner_pubkey: Option<&PublicKey>) -> Result<(), String> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, schnorr::Signature};

        // If no co-signer pubkey provided (BDK ledger), skip verification
        let partner_pubkey = match partner_pubkey {
            Some(pk) => pk,
            None => return Ok(()),
        };

        // If no co-signer signature, skip
        if self.cosign_signature == [0u8; 64] {
            return Ok(());
        }

        let secp = Secp256k1::new();
        let data = self.cosign_data();
        let member_hash = self.member_ledger_hash.unwrap_or([0u8; 32]);

        // BIP-340 tagged hash: SHA256(tag_hash || tag_hash || data || member_ledger_hash)
        let tag = b"deposits/cosign";
        let tag_hash = sha256::Hash::hash(tag);
        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&data);
        tagged_input.extend_from_slice(&member_hash);

        let hash = sha256::Hash::hash(&tagged_input);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_slice(&self.cosign_signature)
            .map_err(|e| format!("Invalid co-signer signature format: {}", e))?;

        let (xonly, _parity) = partner_pubkey.x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| format!("Co-signer signature verification failed: {}", e))
    }

    /// Verify the operator's signature over content + co-signer's signature.
    pub fn verify_operator_signature(&self) -> Result<(), String> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, schnorr::Signature};

        let secp = Secp256k1::new();
        let data = self.operator_signing_data();
        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_slice(&self.operator_signature)
            .map_err(|e| format!("Invalid operator signature format: {}", e))?;

        let (xonly, _parity) = self.operator_id.x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| format!("Operator signature verification failed: {}", e))
    }

    /// Verify both signatures on this update.
    ///
    /// The co-signer pubkey must be provided by the caller (from the Ledger).
    /// For BDK ledgers without a co-signer, pass None.
    pub fn verify_signatures(&self, partner_pubkey: Option<&PublicKey>) -> Result<(), String> {
        self.verify_cosign_signature(partner_pubkey)?;
        self.verify_operator_signature()
    }

    /// Check if this update has valid (non-zero) signatures.
    pub fn is_fully_signed(&self) -> bool {
        self.cosign_signature != [0u8; 64] && self.operator_signature != [0u8; 64]
    }

    /// Check if co-signer has signed (non-zero signature).
    pub fn has_cosign_signature(&self) -> bool {
        self.cosign_signature != [0u8; 64]
    }

    /// Check if operator has signed (non-zero signature).
    pub fn has_operator_signature(&self) -> bool {
        self.operator_signature != [0u8; 64]
    }
}

// ============================================================================
// Deposit Info (API Response)
// ============================================================================

/// Deposit information for API responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositInfo {
    /// Deposit identifier (hex).
    pub deposit_id: String,
    /// Miniscript descriptor.
    pub descriptor: String,
    /// Current balance (millisatoshis).
    pub balance: u64,
    /// Locked balance (millisatoshis).
    pub locked_balance: u64,
    /// Available balance (millisatoshis).
    pub available_balance: u64,
    /// Number of active invoices.
    pub invoice_count: usize,
    /// Fee structure.
    pub fees: FeeStructure,
}

impl From<&Deposit> for DepositInfo {
    fn from(d: &Deposit) -> Self {
        Self {
            deposit_id: hex::encode(d.deposit_id),
            descriptor: d.descriptor.clone(),
            balance: d.balance,
            locked_balance: d.locked_balance,
            available_balance: d.available_balance(),
            invoice_count: d.invoices.len(),
            fees: d.fees.clone(),
        }
    }
}

// ============================================================================
// Quorum Message Types
// ============================================================================

/// Request to join a ledger's quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumJoinRequestMsg {
    /// Requester's public key.
    #[serde(with = "serde_pubkey")]
    pub requester_pubkey: PublicKey,
    /// Operator of the ledger.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_id: String,
    /// Protocol version.
    pub protocol_version: u16,
    /// Timestamp.
    pub timestamp: u64,
    /// Signature.
    #[serde(with = "serde_64")]
    pub signature: [u8; 64],
}

/// Response to a quorum join request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumJoinResponseMsg {
    /// Whether the request was accepted.
    pub accepted: bool,
    /// Current quorum members.
    #[serde(with = "serde_pubkey_vec")]
    pub members: Vec<PublicKey>,
    /// Voting threshold.
    pub threshold: u16,
    /// Last sequence number.
    pub last_sequence: u64,
    /// Current state hash.
    #[serde(with = "serde_32")]
    pub current_hash: [u8; 32],
    /// Rejection reason (if rejected).
    pub rejection_reason: Option<String>,
}

/// A vote in a quorum voting round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumVoteMsg {
    /// Vote round ID.
    #[serde(with = "serde_32")]
    pub vote_round_id: [u8; 32],
    /// Voter's public key.
    #[serde(with = "serde_pubkey")]
    pub voter_pubkey: PublicKey,
    /// Vote value (true = conforming, false = non-conforming).
    pub vote: bool,
    /// Voter's sequence number.
    pub voter_sequence: u64,
    /// Voter's state hash.
    #[serde(with = "serde_32")]
    pub voter_state_hash: [u8; 32],
    /// Evidence (for non-conforming votes).
    pub evidence: Option<Vec<u8>>,
    /// Signature over the vote.
    #[serde(with = "serde_64")]
    pub signature: [u8; 64],
    /// Optional spend signature for recovery.
    #[serde(with = "serde_opt_64")]
    pub spend_signature: Option<[u8; 64]>,
}

// ============================================================================
// Ledger Update (Hash Chain Entry)
// ============================================================================

/// A single ledger update entry - the atomic unit of ledger state transition.
/// The ledger state is derived by applying updates in sequence from genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerUpdate {
    /// Sequential update number (0 for first update, 1 for second, etc.)
    pub sequence_number: u64,
    /// The protocol message that represents this state transition (serialized)
    pub message: Vec<u8>,
    /// Hash of the previous update in the chain (0x0 for genesis/first update)
    #[serde(with = "serde_32")]
    pub previous_hash: [u8; 32],
    /// Hash of this update (computed from sequence_number, message, and previous_hash)
    #[serde(with = "serde_32")]
    pub consensus_hash: [u8; 32],
}

impl LedgerUpdate {
    /// Calculate the hash of this update based on its contents.
    pub fn calculate_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.sequence_number.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(&self.message);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// ============================================================================
// Invoice Info (API Response)
// ============================================================================

/// Invoice information for API responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceInfo {
    /// Invoice ID.
    pub id: String,
    /// Amount in satoshis.
    pub amount: u64,
    /// Expiration time (Unix timestamp).
    pub expires: u64,
    /// Payment hash.
    #[serde(with = "serde_32")]
    pub payment_hash: [u8; 32],
}

// ============================================================================
// Reserves Status (API Response)
// ============================================================================

/// Current reserves status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservesStatus {
    /// Current reserves amount.
    pub current_amount: u64,
    /// Required reserves amount (100% of deposits + max invoice).
    pub required_amount: u64,
    /// Excess reserves that can be removed.
    pub excess_amount: u64,
    /// Total of all deposit balances.
    pub total_deposit_balances: u64,
    /// Largest outstanding invoice amount.
    pub max_outstanding_invoice: u64,
    /// Number of deposits.
    pub deposit_count: usize,
    /// Total locked balances.
    pub total_locked_balances: u64,
}

// ============================================================================
// Signed Ledger Update Log (Audit Trail)
// ============================================================================

/// Cryptographically signed ledger update log for audit trail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerUpdateLog {
    /// Unique ledger identifier: SHA256(genesis_operator || reserves_id || genesis_block).
    #[serde(with = "serde_32")]
    pub ledger_id: [u8; 32],
    /// Chain of signed updates (ordered by sequence number).
    pub updates: Vec<SignedLedgerUpdate>,
    /// Next expected sequence number.
    pub next_sequence: u64,
    /// Buffer for out-of-order updates (keyed by sequence number).
    #[serde(default)]
    pub pending_updates: HashMap<u64, SignedLedgerUpdate>,
}

impl SignedLedgerUpdateLog {
    /// Create a new empty log.
    pub fn new(ledger_id: [u8; 32]) -> Self {
        Self {
            ledger_id,
            updates: Vec::new(),
            next_sequence: 0,
            pending_updates: HashMap::new(),
        }
    }

    /// Get the ledger ID as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    /// Add an update to the log with sequence and hash chain validation.
    ///
    /// Validates that:
    /// - The sequence number matches the expected next sequence
    /// - The previous hash matches the last update's current hash (or zeros if first)
    pub fn add_update(&mut self, update: SignedLedgerUpdate) -> Result<(), crate::DepositsError> {
        // Verify sequence number
        if update.sequence_number != self.next_sequence {
            return Err(crate::DepositsError::InvalidState(
                format!("Sequence mismatch: expected {}, got {}", self.next_sequence, update.sequence_number)
            ));
        }

        // Verify chain continuity (previous hash should match last update's hash)
        let expected_prev = if let Some(last) = self.updates.last() {
            last.current_hash
        } else {
            [0u8; 32]
        };
        if update.previous_hash != expected_prev {
            return Err(crate::DepositsError::InvalidState(
                format!("Hash chain broken: expected {}, got {}",
                    hex::encode(expected_prev), hex::encode(update.previous_hash))
            ));
        }

        // Add to log
        self.updates.push(update);
        self.next_sequence += 1;
        Ok(())
    }

    /// Verify the hash chain integrity of all updates.
    ///
    /// Checks that:
    /// - Sequence numbers are contiguous starting from 0
    /// - Each update's previous_hash matches the prior update's current_hash
    pub fn verify_chain(&self) -> Result<(), crate::DepositsError> {
        let mut expected_prev = [0u8; 32];
        for (i, update) in self.updates.iter().enumerate() {
            if update.sequence_number != i as u64 {
                return Err(crate::DepositsError::InvalidState(
                    format!("Sequence mismatch at index {}: expected {}, got {}", i, i, update.sequence_number)
                ));
            }
            if update.previous_hash != expected_prev {
                return Err(crate::DepositsError::InvalidState(
                    format!("Hash chain broken at index {}", i)
                ));
            }
            expected_prev = update.current_hash;
        }
        Ok(())
    }

    /// Get all updates with sequence numbers greater than the given value.
    pub fn get_updates_since(&self, since_sequence: u64) -> Vec<SignedLedgerUpdate> {
        self.updates
            .iter()
            .filter(|u| u.sequence_number > since_sequence)
            .cloned()
            .collect()
    }

    /// Get the tail (most recent) hash from the update chain.
    ///
    /// Returns zeros if there are no updates yet.
    pub fn tail_hash(&self) -> [u8; 32] {
        self.updates.last()
            .map(|u| u.current_hash)
            .unwrap_or([0u8; 32])
    }

    /// Get the number of updates in this log.
    pub fn len(&self) -> usize {
        self.updates.len()
    }

    /// Check if this log is empty.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }
}

// ============================================================================
// Audit Types
// ============================================================================

/// Result of a ledger audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    /// Detected violations.
    pub violations: Vec<Violation>,
    /// Cross-ledger inconsistencies.
    pub cross_ledger_violations: Vec<CrossLedgerViolation>,
    /// Overall compliance score (0-100).
    pub compliance_score: u8,
    /// Audit timestamp (Unix timestamp).
    pub audit_timestamp: u64,
}

/// Types of protocol violations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Violation {
    /// Insufficient reserves for operation.
    InsufficientReserves { required: u64, actual: u64, timestamp: u64 },
    /// Unauthorized operation without proper signatures.
    UnauthorizedOperation { operation_type: String, timestamp: u64 },
    /// Payment received but not credited to deposit.
    PaymentNotCredited {
        #[serde(with = "serde_32")]
        payment_hash: [u8; 32],
        amount: u64,
        timestamp: u64,
    },
    /// Invalid reserve calculation.
    InvalidReserveCalculation { expected: u64, actual: u64, timestamp: u64 },
    /// Fee assessment violation.
    InvalidFeeAssessment {
        #[serde(with = "serde_deposit_id")]
        deposit_id: DepositId,
        timestamp: u64,
    },
}

/// Cross-ledger violations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossLedgerViolation {
    /// Inconsistent operator behavior across ledgers.
    InconsistentBehavior {
        #[serde(with = "serde_32")]
        ledger1: [u8; 32],
        #[serde(with = "serde_32")]
        ledger2: [u8; 32],
        discrepancy: String,
    },
    /// Reserve manipulation across ledgers.
    ReserveManipulation {
        affected_ledgers: Vec<[u8; 32]>,
        details: String,
    },
}

// ============================================================================
// Ledger State Updates
// ============================================================================

/// Updates that can be applied to ledger state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerStateUpdate {
    /// Add a new deposit.
    AddDeposit(Deposit),
    /// Remove a deposit.
    RemoveDeposit(#[serde(with = "serde_pubkey")] PublicKey),
    /// Update deposit balance.
    UpdateDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        new_balance: u64,
    },
    /// Update reserves amount.
    UpdateReserves(u64),
    /// Set pending invoice.
    SetPendingInvoice(Option<PendingInvoice>),
    /// Lock deposit balance for payment.
    LockDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        amount: u64,
    },
    /// Unlock deposit balance (payment failed).
    UnlockDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        amount: u64,
    },
    /// Add invoice to deposit.
    AddInvoiceToDeposit {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        invoice: Invoice,
    },
    /// Remove invoice from deposit.
    RemoveInvoiceFromDeposit {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        invoice_id: String,
    },
}

// ============================================================================
// TLV Encoding Implementations
// ============================================================================

use crate::tlv::{TlvEncode, TlvDecode, TlvBuilder, TlvReader, TlvResult};

// Field type constants for FeeStructure
mod fee_structure_fields {
    pub const ANNUALIZED_MSATS: u64 = 0;
    pub const ANNUALIZED_BPS: u64 = 2;
    pub const FREQUENCY_BLOCKS: u64 = 4;
}

impl TlvEncode for FeeStructure {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(fee_structure_fields::ANNUALIZED_MSATS, self.annualized_msats)
            .u16_field(fee_structure_fields::ANNUALIZED_BPS, self.annualized_bps)
            .u32_field(fee_structure_fields::FREQUENCY_BLOCKS, self.frequency_blocks)
            .build()
    }
}

impl TlvDecode for FeeStructure {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            annualized_msats: reader.read_u64(fee_structure_fields::ANNUALIZED_MSATS)?,
            annualized_bps: reader.read_u16(fee_structure_fields::ANNUALIZED_BPS)?,
            frequency_blocks: reader.read_u32(fee_structure_fields::FREQUENCY_BLOCKS)?,
        })
    }
}

// Field type constants for TransferFeeSchedule
mod transfer_fee_fields {
    pub const FIXED_MSATS: u64 = 0;
    pub const RATE_BPS: u64 = 2;
}

impl TlvEncode for TransferFeeSchedule {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(transfer_fee_fields::FIXED_MSATS, self.fixed_msats)
            .u16_field(transfer_fee_fields::RATE_BPS, self.rate_bps)
            .build()
    }
}

impl TlvDecode for TransferFeeSchedule {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            fixed_msats: reader.read_u64(transfer_fee_fields::FIXED_MSATS)?,
            rate_bps: reader.read_u16(transfer_fee_fields::RATE_BPS)?,
        })
    }
}

// Field type constants for Invoice
mod invoice_fields {
    pub const ID: u64 = 0;
    pub const PAYMENT_HASH: u64 = 2;
    pub const AMOUNT: u64 = 4;
    pub const EXPIRES: u64 = 6;
    pub const ASSIGNED_DEPOSIT: u64 = 8;
    pub const BOLT11: u64 = 10;
}

impl TlvEncode for Invoice {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .string_field(invoice_fields::ID, &self.id)
            .bytes_field(invoice_fields::PAYMENT_HASH, &self.payment_hash)
            .u64_field(invoice_fields::AMOUNT, self.amount)
            .u64_field(invoice_fields::EXPIRES, self.expires)
            .deposit_id_field(invoice_fields::ASSIGNED_DEPOSIT, &self.assigned_deposit)
            .string_field(invoice_fields::BOLT11, &self.bolt11)
            .build()
    }
}

impl TlvDecode for Invoice {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            id: reader.read_string(invoice_fields::ID)?,
            payment_hash: reader.read_bytes(invoice_fields::PAYMENT_HASH)?,
            amount: reader.read_u64(invoice_fields::AMOUNT)?,
            expires: reader.read_u64(invoice_fields::EXPIRES)?,
            assigned_deposit: reader.read_deposit_id(invoice_fields::ASSIGNED_DEPOSIT)?,
            bolt11: reader.read_string(invoice_fields::BOLT11)?,
        })
    }
}

// Field type constants for PendingInvoice
mod pending_invoice_fields {
    pub const AMOUNT: u64 = 0;
    pub const PAYMENT_HASH: u64 = 2;
    pub const EXPIRES: u64 = 4;
    pub const ASSIGNED_DEPOSIT: u64 = 6;
    pub const INVOICE_ID: u64 = 8;
    pub const BOLT11: u64 = 10;
}

impl TlvEncode for PendingInvoice {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(pending_invoice_fields::AMOUNT, self.amount)
            .bytes_field(pending_invoice_fields::PAYMENT_HASH, &self.payment_hash)
            .u64_field(pending_invoice_fields::EXPIRES, self.expires)
            .deposit_id_field(pending_invoice_fields::ASSIGNED_DEPOSIT, &self.assigned_deposit)
            .string_field(pending_invoice_fields::INVOICE_ID, &self.invoice_id)
            .string_field(pending_invoice_fields::BOLT11, &self.bolt11)
            .build()
    }
}

impl TlvDecode for PendingInvoice {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            amount: reader.read_u64(pending_invoice_fields::AMOUNT)?,
            payment_hash: reader.read_bytes(pending_invoice_fields::PAYMENT_HASH)?,
            expires: reader.read_u64(pending_invoice_fields::EXPIRES)?,
            assigned_deposit: reader.read_deposit_id(pending_invoice_fields::ASSIGNED_DEPOSIT)?,
            invoice_id: reader.read_string(pending_invoice_fields::INVOICE_ID)?,
            bolt11: reader.read_string(pending_invoice_fields::BOLT11)?,
        })
    }
}

// Field type constants for Deposit
mod deposit_fields {
    pub const DEPOSIT_ID: u64 = 0;
    pub const DESCRIPTOR: u64 = 1;
    pub const BALANCE: u64 = 2;
    pub const LOCKED_BALANCE: u64 = 4;
    pub const COLLATERAL_PLEDGE_AMOUNT: u64 = 12;
    pub const COLLATERAL_PLEDGE_EXPIRES: u64 = 14;
    pub const INVOICES: u64 = 6;
    pub const FEES: u64 = 8;
    pub const LAST_FEE_ASSESSMENT: u64 = 10;
    pub const TRANSFER_FEES: u64 = 16;
    pub const IS_COLLATERAL: u64 = 20; // u8 (0 or 1)
    pub const RECEIVE_REQUIRES_SIG: u64 = 22; // u8 (0 or 1)
    pub const FEE_CHANGE_AFTER: u64 = 24; // u32
    pub const FEE_CHANGE_NOTICE: u64 = 26; // u32
    pub const FEE_CHANGE_LIMIT_BPS: u64 = 28; // u16
    pub const OPENED_AT_BLOCK: u64 = 18; // u32
    pub const PENDING_FEE_CHANGE: u64 = 30; // nested
}

impl TlvEncode for Deposit {
    fn tlv_encode(&self) -> Vec<u8> {
        let mut builder = TlvBuilder::new()
            .deposit_id_field(deposit_fields::DEPOSIT_ID, &self.deposit_id)
            .string_field(deposit_fields::DESCRIPTOR, &self.descriptor)
            .u64_field(deposit_fields::BALANCE, self.balance)
            .u64_field(deposit_fields::LOCKED_BALANCE, self.locked_balance)
            .vec_field(deposit_fields::INVOICES, &self.invoices)
            .nested(deposit_fields::FEES, &self.fees)
            .u32_field(deposit_fields::LAST_FEE_ASSESSMENT, self.last_fee_assessment)
            .u64_field(deposit_fields::COLLATERAL_PLEDGE_AMOUNT, self.collateral_lock_amount)
            .u32_field(deposit_fields::COLLATERAL_PLEDGE_EXPIRES, self.collateral_lock_expires)
            .nested(deposit_fields::TRANSFER_FEES, &self.transfer_fees)
            .u8_field(deposit_fields::IS_COLLATERAL, if self.is_collateral { 1 } else { 0 })
            .u8_field(deposit_fields::RECEIVE_REQUIRES_SIG, if self.receive_requires_sig { 1 } else { 0 })
            .u32_field(deposit_fields::OPENED_AT_BLOCK, self.opened_at_block);
        if let Some(v) = self.fee_change_after_blocks {
            builder = builder.u32_field(deposit_fields::FEE_CHANGE_AFTER, v);
        }
        if let Some(v) = self.fee_change_notice_blocks {
            builder = builder.u32_field(deposit_fields::FEE_CHANGE_NOTICE, v);
        }
        if let Some(v) = self.fee_change_limit_bps {
            builder = builder.u16_field(deposit_fields::FEE_CHANGE_LIMIT_BPS, v);
        }
        builder.build()
    }
}

impl TlvDecode for Deposit {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            deposit_id: reader.read_deposit_id(deposit_fields::DEPOSIT_ID)?,
            descriptor: reader.read_string(deposit_fields::DESCRIPTOR)?,
            balance: reader.read_u64(deposit_fields::BALANCE)?,
            locked_balance: reader.read_u64(deposit_fields::LOCKED_BALANCE)?,
            invoices: reader.read_vec(deposit_fields::INVOICES)?,
            fees: reader.read_nested(deposit_fields::FEES)?,
            last_fee_assessment: reader.read_u32(deposit_fields::LAST_FEE_ASSESSMENT)?,
            collateral_lock_amount: reader.read_u64_opt(deposit_fields::COLLATERAL_PLEDGE_AMOUNT)?.unwrap_or(0),
            collateral_lock_expires: reader.read_u32_opt(deposit_fields::COLLATERAL_PLEDGE_EXPIRES)?.unwrap_or(0),
            transfer_fees: reader.read_nested_opt(deposit_fields::TRANSFER_FEES)?.unwrap_or_default(),
            is_collateral: reader.read_u8(deposit_fields::IS_COLLATERAL).unwrap_or(0) != 0,
            receive_requires_sig: reader.read_u8(deposit_fields::RECEIVE_REQUIRES_SIG).unwrap_or(0) != 0,
            fee_change_after_blocks: reader.read_u32_opt(deposit_fields::FEE_CHANGE_AFTER)?,
            fee_change_notice_blocks: reader.read_u32_opt(deposit_fields::FEE_CHANGE_NOTICE)?,
            fee_change_limit_bps: reader.read_u16_opt(deposit_fields::FEE_CHANGE_LIMIT_BPS)?,
            opened_at_block: reader.read_u32_opt(deposit_fields::OPENED_AT_BLOCK)?.unwrap_or(0),
            pending_fee_change: None, // transient state, not serialized in TLV
        })
    }
}

// Field type constants for ReservesOutput
mod reserves_output_fields {
    pub const CHANNEL_ID: u64 = 0;
    pub const AMOUNT: u64 = 2;
    pub const SPEND_TO: u64 = 4;
}

impl TlvEncode for ReservesOutput {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .bytes_field(reserves_output_fields::CHANNEL_ID, &self.channel_id)
            .u64_field(reserves_output_fields::AMOUNT, self.amount)
            .pubkey_field(reserves_output_fields::SPEND_TO, &self.spend_to)
            .build()
    }
}

impl TlvDecode for ReservesOutput {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            channel_id: reader.read_bytes(reserves_output_fields::CHANNEL_ID)?,
            amount: reader.read_u64(reserves_output_fields::AMOUNT)?,
            spend_to: reader.read_pubkey(reserves_output_fields::SPEND_TO)?,
        })
    }
}

// Field type constants for SignedLedgerUpdate
mod signed_update_fields {
    pub const MESSAGE: u64 = 0;
    pub const MESSAGE_TYPE: u64 = 2;
    pub const OPERATOR_ID: u64 = 4;
    pub const LEDGER_ID: u64 = 6;
    pub const SEQUENCE_NUMBER: u64 = 8;
    pub const PREVIOUS_HASH: u64 = 10;
    // 12 was CURRENT_HASH — removed from wire, now derived from content
    pub const COSIGN_SIGNATURE: u64 = 16;
    pub const OPERATOR_SIGNATURE: u64 = 18;
    pub const BLOCK_HEIGHT: u64 = 20;
    pub const BLOCK_HASH: u64 = 22;
    pub const COSIGNER_PUBKEY: u64 = 24;
    pub const MEMBER_LEDGER_HASH: u64 = 26;
}

impl TlvEncode for SignedLedgerUpdate {
    fn tlv_encode(&self) -> Vec<u8> {
        let mut builder = TlvBuilder::new()
            .bytes_field(signed_update_fields::MESSAGE, &self.message)
            .u16_field(signed_update_fields::MESSAGE_TYPE, self.message_type)
            .pubkey_field(signed_update_fields::OPERATOR_ID, &self.operator_id)
            .bytes_field(signed_update_fields::LEDGER_ID, &self.ledger_id)
            .u64_field(signed_update_fields::SEQUENCE_NUMBER, self.sequence_number)
            .bytes_field(signed_update_fields::PREVIOUS_HASH, &self.previous_hash)
            .u32_field(signed_update_fields::BLOCK_HEIGHT, self.block_height)
            .bytes_field(signed_update_fields::BLOCK_HASH, &self.block_hash)
            .bytes_field(signed_update_fields::COSIGN_SIGNATURE, &self.cosign_signature)
            .bytes_field(signed_update_fields::OPERATOR_SIGNATURE, &self.operator_signature);
        if let Some(ref pk) = self.cosigner_pubkey {
            builder = builder.pubkey_field(signed_update_fields::COSIGNER_PUBKEY, pk);
        }
        if let Some(ref hash) = self.member_ledger_hash {
            builder = builder.bytes_field(signed_update_fields::MEMBER_LEDGER_HASH, hash);
        }
        builder.build()
    }
}

impl TlvDecode for SignedLedgerUpdate {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        let mut update = Self {
            message: reader.read_raw(signed_update_fields::MESSAGE)?.to_vec(),
            message_type: reader.read_u16(signed_update_fields::MESSAGE_TYPE)?,
            operator_id: reader.read_pubkey(signed_update_fields::OPERATOR_ID)?,
            ledger_id: reader.read_bytes(signed_update_fields::LEDGER_ID)?,
            sequence_number: reader.read_u64(signed_update_fields::SEQUENCE_NUMBER)?,
            previous_hash: reader.read_bytes(signed_update_fields::PREVIOUS_HASH)?,
            current_hash: [0u8; 32],
            block_height: reader.read_u32_opt(signed_update_fields::BLOCK_HEIGHT)?.unwrap_or(0),
            block_hash: reader.read_bytes_opt(signed_update_fields::BLOCK_HASH)?.unwrap_or([0u8; 32]),
            cosign_signature: reader.read_bytes(signed_update_fields::COSIGN_SIGNATURE)?,
            operator_signature: reader.read_bytes(signed_update_fields::OPERATOR_SIGNATURE)?,
            cosigner_pubkey: reader.read_pubkey_opt(signed_update_fields::COSIGNER_PUBKEY)?,
            member_ledger_hash: reader.read_bytes_opt(signed_update_fields::MEMBER_LEDGER_HASH)?,
        };
        // Derive current_hash from content (not stored on wire)
        update.current_hash = update.compute_hash();
        Ok(update)
    }
}

// Field type constants for CollateralAttestation
mod collateral_attestation_fields {
    pub const OPERATOR_ID: u64 = 0;
    pub const QUORUM_MEMBER: u64 = 2;
    pub const COLLATERAL_LEDGER_ID: u64 = 3;
    pub const AMOUNT: u64 = 4;
    pub const BLOCK_HEIGHT: u64 = 6;
    pub const LOCK_UNTIL_BLOCK: u64 = 7;
    pub const SIGNATURE: u64 = 8;
    pub const LEDGER_HASH: u64 = 10;
}

impl TlvEncode for CollateralAttestation {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .pubkey_field(collateral_attestation_fields::OPERATOR_ID, &self.operator_id)
            .pubkey_field(collateral_attestation_fields::QUORUM_MEMBER, &self.quorum_member)
            .string_field(collateral_attestation_fields::COLLATERAL_LEDGER_ID, &self.collateral_ledger_id)
            .u64_field(collateral_attestation_fields::AMOUNT, self.amount)
            .u32_field(collateral_attestation_fields::BLOCK_HEIGHT, self.block_height)
            .u32_field(collateral_attestation_fields::LOCK_UNTIL_BLOCK, self.lock_until_block)
            .bytes_field(collateral_attestation_fields::SIGNATURE, &self.signature)
            .bytes_field(collateral_attestation_fields::LEDGER_HASH, &self.ledger_hash)
            .build()
    }
}

impl TlvDecode for CollateralAttestation {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            operator_id: reader.read_pubkey(collateral_attestation_fields::OPERATOR_ID)?,
            quorum_member: reader.read_pubkey(collateral_attestation_fields::QUORUM_MEMBER)?,
            collateral_ledger_id: reader.read_string_opt(collateral_attestation_fields::COLLATERAL_LEDGER_ID)?.unwrap_or_default(),
            amount: reader.read_u64(collateral_attestation_fields::AMOUNT)?,
            block_height: reader.read_u32(collateral_attestation_fields::BLOCK_HEIGHT)?,
            lock_until_block: reader.read_u32_opt(collateral_attestation_fields::LOCK_UNTIL_BLOCK)?.unwrap_or(0),
            signature: reader.read_bytes(collateral_attestation_fields::SIGNATURE)?,
            ledger_hash: reader.read_bytes(collateral_attestation_fields::LEDGER_HASH)?,
        })
    }
}

// ============================================================================
// Commitment Extra Output
// ============================================================================

/// Extra output to be added to commitment transactions (for reserves).
/// This is a deposits-core equivalent of lightning::ln::chan_utils::CommitmentExtraOutput.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentExtraOutput {
    /// Amount in satoshis for this output.
    pub amount_satoshis: u64,
    /// Script pubkey for this output.
    pub script_pubkey: bitcoin::ScriptBuf,
}

// ============================================================================
// Channel ID
// ============================================================================

/// A 32-byte channel identifier.
/// This is a deposits-core equivalent of lightning::ln::types::ChannelId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ChannelId(pub [u8; 32]);

impl ChannelId {
    /// Create a new ChannelId from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the inner bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ChannelId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ChannelId> for [u8; 32] {
    fn from(id: ChannelId) -> Self {
        id.0
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ============================================================================
// Deposit Offer (On-Chain Funding Commitment)
// ============================================================================

/// A signed offer to credit a deposit with on-chain funds.
///
/// This structure represents an operator's commitment to credit a deposit
/// with funds sent to a specific Bitcoin address, up to a maximum amount,
/// before a deadline block height. The offer is signed by the operator,
/// creating a verifiable commitment.
///
/// Used for on-chain deposit funding (without Lightning invoices).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositOffer {
    /// The operator making the offer.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,

    /// The ledger ID (64-char hex hash stable across custody transfers).
    pub ledger_id: String,

    /// The deposit_id (identifier for the deposit).
    #[serde(with = "serde_deposit_id")]
    pub deposit_id: DepositId,

    /// The descriptor controlling this deposit.
    pub descriptor: String,

    /// Bitcoin address to receive funds (bech32 or other address format).
    pub funding_address: String,

    /// Maximum amount in satoshis that will be credited.
    pub max_amount_sats: u64,

    /// Minimum amount in satoshis (to cover processing costs).
    pub min_amount_sats: u64,

    /// Deadline block height - offer expires after this block.
    pub deadline_block: u32,

    /// Block height when offer was created.
    pub created_at_block: u32,

    /// Unique offer ID (hash of offer parameters before signature).
    #[serde(with = "serde_32")]
    pub offer_id: [u8; 32],

    /// Operator's signature over the offer commitment.
    /// Signs: "DEPOSIT_OFFER:{offer_id}:{operator}:{ledger}:{deposit_id}:{address}:{max}:{min}:{deadline}"
    #[serde(with = "serde_64")]
    pub operator_signature: [u8; 64],

    /// Fee structure for the deposit (established at offer creation).
    #[serde(default)]
    pub fees: Option<FeeStructure>,

    /// Per-transfer fee schedule (established at offer creation).
    #[serde(default)]
    pub transfer_fees: Option<TransferFeeSchedule>,
}

impl DepositOffer {
    /// Create the message to be signed for an offer.
    ///
    /// Returns the canonical message format that should be signed by the operator.
    pub fn signing_message(
        operator_id: &PublicKey,
        ledger_id: &str,
        deposit_id: &DepositId,
        funding_address: &str,
        max_amount_sats: u64,
        min_amount_sats: u64,
        deadline_block: u32,
    ) -> String {
        // Create a deterministic message that commits to all offer parameters
        format!(
            "DEPOSIT_OFFER:{}:{}:{}:{}:{}:{}:{}",
            hex::encode(operator_id.serialize()),
            ledger_id,
            hex::encode(deposit_id),
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        )
    }

    /// Compute the offer ID from the signing message.
    pub fn compute_offer_id(signing_message: &str) -> [u8; 32] {
        let hash = sha256::Hash::hash(signing_message.as_bytes());
        hash.to_byte_array()
    }

    /// Check if the offer has expired.
    pub fn is_expired(&self, current_block: u32) -> bool {
        current_block > self.deadline_block
    }

    /// Check if an amount is within the offer's limits.
    pub fn is_amount_valid(&self, amount_sats: u64) -> bool {
        amount_sats >= self.min_amount_sats && amount_sats <= self.max_amount_sats
    }

    /// Get the signing message for this offer.
    pub fn get_signing_message(&self) -> String {
        Self::signing_message(
            &self.operator_id,
            &self.ledger_id,
            &self.deposit_id,
            &self.funding_address,
            self.max_amount_sats,
            self.min_amount_sats,
            self.deadline_block,
        )
    }
}

/// Status of a deposit offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositOfferStatus {
    /// Offer is active and awaiting funding.
    Pending,
    /// Funds have been received and are awaiting confirmation.
    FundingReceived {
        /// Transaction ID of the funding transaction.
        txid: String,
        /// Amount received in satoshis.
        amount_sats: u64,
        /// Block height when payment was detected.
        detected_at_block: u32,
    },
    /// Funds have been confirmed and deposit credited.
    Completed {
        /// Transaction ID of the funding transaction.
        txid: String,
        /// Amount credited in satoshis.
        amount_sats: u64,
        /// Block height when confirmed.
        confirmed_at_block: u32,
    },
    /// Offer expired without funding.
    Expired {
        /// Block height when expired.
        expired_at_block: u32,
    },
    /// Offer was cancelled by the operator.
    Cancelled,
}

// ============================================================================
// On-Chain Withdrawal (Deposit -> Bitcoin Address)
// ============================================================================

/// A request to withdraw funds from a deposit to a Bitcoin address.
///
/// This is the on-chain equivalent of paying a Lightning invoice.
/// The flow is:
/// 1. Lock: Reserve funds in the deposit for the withdrawal
/// 2. Complete: Broadcast the transaction and record the txid as evidence
///
/// Unlike Lightning, there's no "fail" after broadcast - the transaction
/// either confirms or we wait. Cancellation is only possible before broadcast.
///
/// The transaction MUST include an OP_RETURN output with the withdrawal_id
/// to prove the operator executed this specific withdrawal request and didn't
/// just wait for a coincidental payment to the same address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainWithdrawal {
    /// Unique withdrawal ID (hash of withdrawal parameters + nonce).
    /// This MUST appear in an OP_RETURN output of the fulfilling transaction.
    #[serde(with = "serde_32")]
    pub withdrawal_id: [u8; 32],

    /// Random nonce to ensure withdrawal_id uniqueness.
    /// Generated by the depositor when creating the withdrawal request.
    #[serde(with = "serde_32")]
    pub nonce: [u8; 32],

    /// The deposit_id withdrawing funds.
    #[serde(with = "serde_deposit_id")]
    pub deposit_id: DepositId,

    /// Bitcoin address to send funds to.
    pub destination_address: String,

    /// Amount to withdraw in satoshis.
    pub amount_sats: u64,

    /// Fee to pay for the transaction in satoshis.
    pub fee_sats: u64,

    /// Block height when withdrawal was requested.
    pub requested_at_block: u32,

    /// Optional memo/description.
    pub memo: Option<String>,

    /// Witness satisfying the deposit descriptor to authorize withdrawal.
    pub depositor_witness: DescriptorWitness,
}

impl OnChainWithdrawal {
    /// Create the message to be signed for a withdrawal authorization.
    ///
    /// The nonce ensures each withdrawal request is unique, even if the
    /// same depositor requests the same amount to the same address twice.
    pub fn signing_message(
        nonce: &[u8; 32],
        deposit_id: &DepositId,
        destination_address: &str,
        amount_sats: u64,
        fee_sats: u64,
    ) -> String {
        format!(
            "WITHDRAWAL:{}:{}:{}:{}:{}",
            hex::encode(nonce),
            hex::encode(deposit_id),
            destination_address,
            amount_sats,
            fee_sats,
        )
    }

    /// Compute the withdrawal ID from the signing message.
    ///
    /// The withdrawal_id uniquely identifies this withdrawal request and
    /// MUST be included in an OP_RETURN output of the fulfilling transaction.
    pub fn compute_withdrawal_id(signing_message: &str) -> [u8; 32] {
        let hash = sha256::Hash::hash(signing_message.as_bytes());
        hash.to_byte_array()
    }

    /// Get the signing message for this withdrawal.
    pub fn get_signing_message(&self) -> String {
        Self::signing_message(
            &self.nonce,
            &self.deposit_id,
            &self.destination_address,
            self.amount_sats,
            self.fee_sats,
        )
    }

    /// Total amount debited from deposit (amount + fee).
    pub fn total_debit(&self) -> u64 {
        self.amount_sats.saturating_add(self.fee_sats)
    }

    /// Get the OP_RETURN data that must be included in the transaction.
    ///
    /// Format: "WDRL:" + withdrawal_id (first 28 bytes to fit in 80 byte OP_RETURN)
    /// This proves the transaction was made specifically for this withdrawal.
    /// Returns a 33-byte array: 5 bytes prefix + 28 bytes of withdrawal_id.
    pub fn op_return_data(&self) -> [u8; 33] {
        let mut data = [0u8; 33];
        data[0..5].copy_from_slice(b"WDRL:");
        data[5..33].copy_from_slice(&self.withdrawal_id[..28]); // 5 + 28 = 33 bytes
        data
    }

    /// Verify that a transaction contains the required OP_RETURN commitment.
    ///
    /// Returns true if the transaction has an OP_RETURN output containing
    /// the withdrawal_id, proving it was made for this specific withdrawal.
    pub fn verify_op_return(&self, op_return_data: &[u8]) -> bool {
        let expected = self.op_return_data();
        op_return_data == &expected[..]
    }
}

/// Status of an on-chain withdrawal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnChainWithdrawalStatus {
    /// Withdrawal is pending - funds locked in deposit.
    Locked {
        /// Block height when locked.
        locked_at_block: u32,
    },

    /// Transaction has been broadcast.
    Broadcast {
        /// Transaction ID.
        txid: String,
        /// Block height when broadcast.
        broadcast_at_block: u32,
    },

    /// Transaction has been confirmed - withdrawal complete.
    Completed {
        /// Transaction ID.
        txid: String,
        /// Block height when confirmed.
        confirmed_at_block: u32,
        /// Number of confirmations.
        confirmations: u32,
    },

    /// Withdrawal was cancelled before broadcast (funds unlocked).
    Cancelled {
        /// Block height when cancelled.
        cancelled_at_block: u32,
        /// Reason for cancellation.
        reason: String,
    },
}

/// Result of locking funds for an on-chain withdrawal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalLockResult {
    /// The withdrawal request.
    pub withdrawal: OnChainWithdrawal,
    /// Previous deposit balance (millisatoshis).
    pub previous_balance_msats: u64,
    /// New deposit balance after lock (millisatoshis).
    pub new_balance_msats: u64,
    /// Amount locked (millisatoshis).
    pub locked_amount_msats: u64,
}

/// Result of completing an on-chain withdrawal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCompleteResult {
    /// The withdrawal ID.
    #[serde(with = "serde_32")]
    pub withdrawal_id: [u8; 32],
    /// Transaction ID of the broadcast transaction.
    pub txid: String,
    /// Amount withdrawn (satoshis).
    pub amount_sats: u64,
    /// Fee paid (satoshis).
    pub fee_sats: u64,
    /// Final deposit balance (millisatoshis).
    pub final_balance_msats: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_fee_calculation() {
        let fees = FeeStructure::new(52560, 100, 144); // 1 sat/block fixed, 1% annual

        // One year of blocks
        let fee = fees.calculate_fee(1_000_000, 52560);
        // Should be ~52560 (fixed) + ~10000 (1% of 1M)
        assert!(fee > 60000 && fee < 65000);
    }

    #[test]
    fn test_deposit_operations() {
        let pk = test_pubkey();
        let mut deposit = Deposit::from_pubkey(&pk, None);

        // Credit
        deposit.credit(100_000);
        assert_eq!(deposit.balance, 100_000);

        // Lock
        deposit.lock(30_000).unwrap();
        assert_eq!(deposit.locked_balance, 30_000);
        assert_eq!(deposit.available_balance(), 70_000);

        // Can't lock more than available
        assert!(deposit.lock(80_000).is_err());

        // Unlock
        deposit.unlock(30_000);
        assert_eq!(deposit.locked_balance, 0);

        // Debit
        deposit.debit(50_000).unwrap();
        assert_eq!(deposit.balance, 50_000);
    }

    #[test]
    fn test_ledger_state() {
        let op = test_pubkey();
        let partner = test_pubkey();
        let mut state = LedgerState::new(op, partner.to_string(), 0);

        assert_eq!(state.total_deposit_balance(), 0);
        assert_eq!(state.reserves_amount(), 0);
        assert!(state.has_sufficient_reserves()); // No deposits means 0 reserves is sufficient

        // Add reserves
        state.reserves = ReservesOutput::new([0u8; 32], 100_000, op);
        assert_eq!(state.reserves_amount(), 100_000);
    }

    #[test]
    fn test_signed_update_hash() {
        let pk = test_pubkey();
        let update = SignedLedgerUpdate {
            message: vec![1, 2, 3],
            message_type: 1,
            operator_id: pk,
            ledger_id: [0x12; 32],
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
        };

        let hash = update.compute_hash();
        assert_ne!(hash, [0u8; 32]); // Hash should be computed
    }

    #[test]
    fn test_signed_update_signature_methods() {
        let pk = test_pubkey();
        let mut update = SignedLedgerUpdate {
            message: vec![1, 2, 3],
            message_type: 1,
            operator_id: pk,
            ledger_id: [0x12; 32],
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
        };

        // Test signing data generation
        let cosign_data = update.cosign_data();
        assert!(!cosign_data.is_empty());

        let operator_data = update.operator_signing_data();
        // Operator data includes cosign_signature
        assert!(operator_data.len() > cosign_data.len());
        assert_eq!(operator_data.len(), cosign_data.len() + 64);

        // Test signature status checks
        assert!(!update.is_fully_signed());
        assert!(!update.has_cosign_signature());
        assert!(!update.has_operator_signature());

        // Set non-zero signatures and check
        update.cosign_signature = [0xaa; 64];
        assert!(update.has_cosign_signature());
        assert!(!update.is_fully_signed());

        update.operator_signature = [0xbb; 64];
        assert!(update.has_operator_signature());
        assert!(update.is_fully_signed());
    }

    #[test]
    fn test_serde_roundtrip() {
        let fees = FeeStructure::new(1000, 50, 144);
        let json = serde_json::to_string(&fees).unwrap();
        let decoded: FeeStructure = serde_json::from_str(&json).unwrap();
        assert_eq!(fees, decoded);
    }

    // TLV roundtrip tests
    #[test]
    fn test_fee_structure_tlv_roundtrip() {
        let original = FeeStructure::new(1000, 50, 144);
        let encoded = original.tlv_encode();
        let decoded = FeeStructure::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invoice_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = Invoice {
            id: "test-invoice-123".to_string(),
            payment_hash: [0xab; 32],
            amount: 100_000,
            expires: 1700000000,
            assigned_deposit: deposit_id,
            bolt11: "lnbc100n1...".to_string(),
        };
        let encoded = original.tlv_encode();
        let decoded = Invoice::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_pending_invoice_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = PendingInvoice {
            amount: 50_000,
            payment_hash: [0xcd; 32],
            expires: 1700001000,
            assigned_deposit: deposit_id,
            invoice_id: "pending-456".to_string(),
            bolt11: "lnbc1...".to_string(),
        };
        let encoded = original.tlv_encode();
        let decoded = PendingInvoice::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = Deposit {
            deposit_id,
            descriptor,
            balance: 1_000_000,
            locked_balance: 50_000,
            invoices: vec![
                Invoice {
                    id: "inv1".to_string(),
                    payment_hash: [0x11; 32],
                    amount: 10_000,
                    expires: 1700000000,
                    assigned_deposit: deposit_id,
                    bolt11: "lnbc10n1...".to_string(),
                },
            ],
            fees: FeeStructure::new(100, 25, 2016),
            last_fee_assessment: 800_000,
            collateral_lock_amount: 500_000,
            collateral_lock_expires: 850_000,
            transfer_fees: TransferFeeSchedule::default(),
            is_collateral: true,
            receive_requires_sig: false,
            fee_change_after_blocks: Some(52560),
            fee_change_notice_blocks: Some(2016),
            fee_change_limit_bps: Some(1000),
            opened_at_block: 100,
            pending_fee_change: None,
        };
        let encoded = original.tlv_encode();
        let decoded = Deposit::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_reserves_output_tlv_roundtrip() {
        let pk = test_pubkey();
        let original = ReservesOutput {
            channel_id: [0x42; 32],
            amount: 5_000_000,
            spend_to: pk,
        };
        let encoded = original.tlv_encode();
        let decoded = ReservesOutput::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_collateral_attestation_tlv_roundtrip() {
        let pk = test_pubkey();
        let original = CollateralAttestation {
            operator_id: pk,
            quorum_member: pk,
            collateral_ledger_id: "test_ledger_id".to_string(),
            amount: 1_000_000,
            block_height: 800_000,
            lock_until_block: 900_000,
            signature: [0xaa; 64],
            ledger_hash: [0xbb; 32],
        };
        let encoded = original.tlv_encode();
        let decoded = CollateralAttestation::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey_3() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_collateral_attestation_methods() {
        let attestation = CollateralAttestation {
            operator_id: test_pubkey(),
            quorum_member: test_pubkey_2(),
            collateral_ledger_id: String::new(),
            amount: 100_000,
            block_height: 800_000,
            lock_until_block: 900_000,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        assert_eq!(attestation.available_collateral(), 100_000);
        assert!(attestation.is_recent(800_100, 200));
        assert!(!attestation.is_recent(800_300, 200));
    }

    #[test]
    fn test_ledger_state_collateral_tracking() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut state = LedgerState::new(op, partner.to_string(), 0);

        // Add quorum members
        let collateral1 = test_pubkey_2();
        let collateral2 = test_pubkey_3();
        state.quorum_members = vec![
            QuorumMember { pubkey: collateral1, ledger_id: String::new(), min_fee_bps: None, min_fee_fixed: None, max_fee_period: None, collateral_lock_amount: None, collateral_lock_until: None, dispute_response_blocks: None, dispute_arm_blocks: None, service_response_blocks: None, max_transfer_timeout_blocks: None, max_descriptor_bytes: None },
            QuorumMember { pubkey: collateral2, ledger_id: String::new(), min_fee_bps: None, min_fee_fixed: None, max_fee_period: None, collateral_lock_amount: None, collateral_lock_until: None, dispute_response_blocks: None, dispute_arm_blocks: None, service_response_blocks: None, max_transfer_timeout_blocks: None, max_descriptor_bytes: None },
        ];

        // Add attestation for collateral1
        let attestation1 = CollateralAttestation::new(
            op,
            collateral1,
            String::new(),
            50_000,
            800_000,
            0, // lock_until_block
            [0u8; 64],
            [0u8; 32],
        );
        state.update_collateral_attestation(collateral1, attestation1).unwrap();

        // Check available collateral
        assert_eq!(state.total_available_collateral(800_100, 200), 50_000);
        assert_eq!(state.partner_available_collateral(&collateral1), Some(50_000));
        assert_eq!(state.partner_available_collateral(&collateral2), None);

        // Check missing attestations
        let missing = state.missing_attestations(800_100, 200);
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&collateral2));

        // Add second attestation
        let attestation2 = CollateralAttestation::new(
            op,
            collateral2,
            String::new(),
            30_000,
            800_000,
            0, // lock_until_block
            [0u8; 64],
            [0u8; 32],
        );
        state.update_collateral_attestation(collateral2, attestation2).unwrap();

        // Now both have attestations
        assert_eq!(state.total_available_collateral(800_100, 200), 80_000);
        assert!(state.missing_attestations(800_100, 200).is_empty());

        // Stale attestations should not count
        assert_eq!(state.total_available_collateral(800_400, 200), 0);
        assert_eq!(state.missing_attestations(800_400, 200).len(), 2);
    }

    // ========================================================================
    // Dispute State Tests
    // ========================================================================

    #[test]
    fn test_dispute_state_allows_operations() {
        // Normal state
        assert!(DisputeState::Normal.allows_operations());
        assert!(DisputeState::Normal.allows_operation(10)); // Some random op
        assert!(!DisputeState::Normal.allows_operation(55)); // DisputeAcquire
        assert!(!DisputeState::Normal.allows_operation(56)); // DisputeYield
        assert!(!DisputeState::Normal.allows_operation(57)); // DisputeArmed

        // Disputed state - only QuorumAddMember(43), CollateralAttestation(42), DisputeArmed(57)
        assert!(DisputeState::Disputed.allows_operations());
        assert!(DisputeState::Disputed.allows_operation(42)); // CollateralAttestation
        assert!(DisputeState::Disputed.allows_operation(43)); // QuorumAddMember
        assert!(DisputeState::Disputed.allows_operation(57)); // DisputeArmed
        assert!(!DisputeState::Disputed.allows_operation(10)); // Random op blocked
        assert!(!DisputeState::Disputed.allows_operation(55)); // DisputeAcquire

        // Armed state - only DisputeAcquire(55) or DisputeYield(56)
        assert!(DisputeState::Armed.allows_operations());
        assert!(DisputeState::Armed.allows_operation(55)); // DisputeAcquire
        assert!(DisputeState::Armed.allows_operation(56)); // DisputeYield
        assert!(!DisputeState::Armed.allows_operation(43)); // QuorumAddMember blocked
        assert!(!DisputeState::Armed.allows_operation(57)); // DisputeArmed blocked

        // Tombstoned - nothing allowed
        assert!(!DisputeState::Tombstoned.allows_operations());
        assert!(!DisputeState::Tombstoned.allows_operation(55));
        assert!(!DisputeState::Tombstoned.allows_operation(56));
    }

    #[test]
    fn test_entropy_selection_deterministic() {
        let entropy_hash = [0x42u8; 32];

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let pk2 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap());
        let pk3 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap());

        let candidates = vec![pk1, pk2, pk3];

        // Selection should be deterministic
        let winner1 = select_entropy_winner(&entropy_hash, &candidates);
        let winner2 = select_entropy_winner(&entropy_hash, &candidates);
        assert_eq!(winner1, winner2);

        // Order shouldn't matter
        let reversed = vec![pk3, pk2, pk1];
        let winner3 = select_entropy_winner(&entropy_hash, &reversed);
        assert_eq!(winner1, winner3);
    }

    #[test]
    fn test_entropy_selection_different_hashes() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let pk2 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap());

        let candidates = vec![pk1, pk2];

        // Different entropy hashes should (usually) produce different winners
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];

        // Note: It's possible both produce the same winner, but unlikely
        // Just verify both return Some
        assert!(select_entropy_winner(&hash1, &candidates).is_some());
        assert!(select_entropy_winner(&hash2, &candidates).is_some());
    }

    #[test]
    fn test_is_entropy_winner() {
        let entropy_hash = [0x42u8; 32];

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let pk2 = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap());

        let candidates = vec![pk1, pk2];
        let winner = select_entropy_winner(&entropy_hash, &candidates).unwrap();

        // Winner should report as winner
        assert!(is_entropy_winner(&entropy_hash, &winner, &candidates));

        // Loser should not report as winner
        let loser = if winner == pk1 { pk2 } else { pk1 };
        assert!(!is_entropy_winner(&entropy_hash, &loser, &candidates));
    }

    #[test]
    fn test_entropy_selection_empty() {
        let entropy_hash = [0x42u8; 32];
        let candidates: Vec<PublicKey> = vec![];

        assert!(select_entropy_winner(&entropy_hash, &candidates).is_none());
    }
}
