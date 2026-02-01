// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core data types for the Bitcoin Deposits Protocol.
//!
//! These types are Lightning-implementation agnostic and use serde for serialization.

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
// Fee Structure
// ============================================================================

/// Fee structure for a deposit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStructure {
    /// Fixed annual fee in satoshis.
    pub annualized_fixed: u64,
    /// Percentage fee in basis points (0.01% = 1 bps).
    pub annualized_bps: u16,
    /// How often fees are assessed (in blocks).
    pub frequency_blocks: u32,
}

impl Default for FeeStructure {
    fn default() -> Self {
        Self {
            annualized_fixed: 0,
            annualized_bps: 0,
            frequency_blocks: 2016, // ~2 weeks
        }
    }
}

impl FeeStructure {
    /// Create a new fee structure.
    pub fn new(annualized_fixed: u64, annualized_bps: u16, frequency_blocks: u32) -> Self {
        Self {
            annualized_fixed,
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
        let fixed_fee = (self.annualized_fixed * blocks) / BLOCKS_PER_YEAR;

        // Percentage fee portion (pro-rated)
        let bps_fee = (balance * self.annualized_bps as u64 * blocks) / (BLOCKS_PER_YEAR * 10000);

        fixed_fee + bps_fee
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
    #[serde(with = "serde_pubkey")]
    pub assigned_deposit: PublicKey,
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
    #[serde(with = "serde_pubkey")]
    pub assigned_deposit: PublicKey,
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
// Deposit
// ============================================================================

/// A user deposit in the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// User's public key (deposit identifier).
    #[serde(with = "serde_pubkey")]
    pub pubkey: PublicKey,
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
}

impl Deposit {
    /// Create a new deposit.
    pub fn new(pubkey: PublicKey, fees: Option<FeeStructure>) -> Self {
        Self {
            pubkey,
            balance: 0,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: fees.unwrap_or_default(),
            last_fee_assessment: 0,
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
        }
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
    /// Amount held in reserves (satoshis).
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
/// - The quorum member's ledger has: QuorumJoin { operator_id, reserves_id, signature }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumMembership {
    /// The operator whose quorum we joined.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// The ledger identifier we're monitoring.
    pub reserves_id: String,
    /// Block height when our membership commitment expires.
    /// After this block, we are no longer obligated to monitor this ledger.
    pub membership_expires: u32,
    /// Our consent signature (matches quorum_member_signature in QuorumAddMember).
    #[serde(with = "serde_64")]
    pub our_signature: [u8; 64],
    /// Sequence number when we joined (for audit trail).
    pub joined_at_sequence: u64,
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
        amount: u64,
        block_height: u32,
        lock_until_block: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    ) -> Self {
        Self {
            operator_id,
            quorum_member,
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
// Ledger State
// ============================================================================

/// Complete state of a Bitcoin Deposits ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    /// Operator's public key.
    #[serde(with = "serde_pubkey")]
    pub operator_key: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_key: String,
    /// Ledger address (as string).
    pub ledger_address: String,
    /// All deposits in this ledger, keyed by depositor's public key.
    #[serde(with = "serde_pubkey_map")]
    pub deposits: HashMap<PublicKey, Deposit>,
    /// Current reserves output.
    pub reserves: ReservesOutput,
    /// Pending invoice awaiting payment.
    pub pending_invoice: Option<PendingInvoice>,
    /// Quorum members who provide additional backing.
    #[serde(with = "serde_pubkey_vec")]
    pub quorum_members: Vec<PublicKey>,
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
    /// - Collateral SIZE requirements are NOT enforced (quorum members don't need ledgers >= half size)
    /// - The 51% security threshold is NOT guaranteed
    ///
    /// After this block:
    /// - Full collateral size requirements enforced
    /// - 51% capital threshold applies
    /// - Non-compliant partner relationships are invalid
    ///
    /// This enables network bootstrap where operators can cross-establish collateral
    /// before the requirements kick in. Set to None for immediate enforcement (joining
    /// an established network), or Some(future_block) for bootstrap phase.
    #[serde(default)]
    pub collateral_enforcement_block: Option<u64>,
    /// Collateral received from other operators that backs this ledger's deposits.
    /// In the 100%+100% model, deposits need 100% reserves + 100% received collateral.
    #[serde(default)]
    pub received_collateral_amount: u64,
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
    /// Current sequence number.
    pub sequence: u64,
    /// Current ledger hash.
    #[serde(with = "serde_32")]
    pub hash: [u8; 32],
    /// Quorums we have joined as a monitoring member.
    /// Records our commitment to monitor other operators' ledgers.
    #[serde(default)]
    pub joined_quorums: Vec<QuorumMembership>,
}

impl LedgerState {
    /// Create a new empty ledger state.
    pub fn new(operator_key: PublicKey, reserves_key: String, ledger_address: String) -> Self {
        Self::with_enforcement_block(operator_key, reserves_key, ledger_address, None)
    }

    /// Create a new ledger state with explicit collateral enforcement block.
    ///
    /// - `enforcement_block = None`: Immediate enforcement (for joining established networks)
    /// - `enforcement_block = Some(future_block)`: Deferred enforcement (for bootstrap)
    pub fn with_enforcement_block(
        operator_key: PublicKey,
        reserves_key: String,
        ledger_address: String,
        collateral_enforcement_block: Option<u64>,
    ) -> Self {
        Self {
            operator_key,
            reserves_key,
            ledger_address,
            deposits: HashMap::new(),
            reserves: ReservesOutput::default(),
            pending_invoice: None,
            quorum_members: Vec::new(),
            collateral_amount: 0,
            last_collateral_increase_block: None,
            collateral_enforcement_block,
            received_collateral_amount: 0,
            collateral_attestations: HashMap::new(),
            partner_deepest_ack_hash: [0u8; 32],
            channel_deepest_commitment_hash: [0u8; 32],
            last_updated: 0,
            pending_updates: HashMap::new(),
            sequence: 0,
            hash: [0u8; 32],
            joined_quorums: Vec::new(),
        }
    }

    /// Check if collateral size requirements are enforced at the given block.
    ///
    /// Returns true if:
    /// - No enforcement block is set (immediate enforcement), OR
    /// - Current block >= enforcement block
    pub fn is_collateral_enforced(&self, current_block: u64) -> bool {
        match self.collateral_enforcement_block {
            None => true, // Immediate enforcement
            Some(enforcement_block) => current_block >= enforcement_block,
        }
    }

    /// Get total balance across all deposits (millisatoshis).
    pub fn total_deposit_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.balance).sum()
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.locked_balance).sum()
    }

    /// Get reserves amount (satoshis).
    pub fn reserves_amount(&self) -> u64 {
        self.reserves.amount
    }

    /// Check if reserves are sufficient.
    pub fn has_sufficient_reserves(&self) -> bool {
        // Convert deposits from msat to sat for comparison
        let total_deposits_sat = self.total_deposit_balance() / 1000;
        self.reserves_amount() >= total_deposits_sat
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
        if !self.quorum_members.contains(&partner) {
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
            .filter(|partner| {
                match self.collateral_attestations.get(partner) {
                    None => true,
                    Some(a) => !a.is_recent(current_block, max_age_blocks),
                }
            })
            .copied()
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
    /// Operator's public key (Lightning node ID).
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_id: String,
    /// Deterministic sequence number (starts at 0 for LedgerOpened).
    pub sequence_number: u64,
    /// Hash of previous ledger state (creates cryptographic chain).
    #[serde(with = "serde_32")]
    pub previous_hash: [u8; 32],
    /// Hash of current ledger state after this update.
    #[serde(with = "serde_32")]
    pub current_hash: [u8; 32],
    /// Timestamp when operator created this update.
    pub timestamp: u64,
    /// Block height when this update was created.
    #[serde(default)]
    pub block_height: u32,
    /// Block hash at the time this update was created.
    #[serde(default, with = "serde_32")]
    pub block_hash: [u8; 32],
    /// Partner's signature over update content.
    #[serde(with = "serde_64")]
    pub partner_signature: [u8; 64],
    /// Operator's final signature covering partner's signature.
    #[serde(with = "serde_64")]
    pub operator_signature: [u8; 64],
}

impl SignedLedgerUpdate {
    /// Compute the hash of this update.
    pub fn compute_hash(&self) -> [u8; 32] {
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

    /// Verify the hash chain.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.current_hash
    }

    // ========================================================================
    // Signature Methods
    // ========================================================================

    /// Compute the data that the partner signs (update content only, no operator signature).
    ///
    /// Partner signs: message || message_type || sequence || prev_hash || curr_hash || timestamp
    /// Partner signs ONLY the content, NOT any operator signature.
    /// This prevents operator from tricking partner into endorsing invalid state.
    pub fn partner_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.message);
        data.extend_from_slice(&self.message_type.to_le_bytes());
        data.extend_from_slice(&self.sequence_number.to_le_bytes());
        data.extend_from_slice(&self.previous_hash);
        data.extend_from_slice(&self.current_hash);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    /// Compute the data that the operator signs (content + partner signature).
    ///
    /// Operator signs: partner_signing_data || partner_signature
    /// This seals the bilateral agreement and proves operator accepted partner's validation.
    pub fn operator_signing_data(&self) -> Vec<u8> {
        let mut data = self.partner_signing_data();
        data.extend_from_slice(&self.partner_signature);
        data
    }

    /// Verify the partner's signature over the update content.
    /// Note: For BDK ledgers where reserves_id is an address (not a pubkey),
    /// this returns an error since there's no partner to verify against.
    pub fn verify_partner_signature(&self) -> Result<(), String> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, ecdsa::Signature, PublicKey};
        use std::str::FromStr;

        // Parse reserves_id as a pubkey - fails for BDK ledgers with address-based IDs
        let partner_pubkey = PublicKey::from_str(&self.reserves_id)
            .map_err(|_| format!("Cannot verify partner signature: reserves_id '{}' is not a valid pubkey (BDK ledger?)", self.reserves_id))?;

        let secp = Secp256k1::new();
        let data = self.partner_signing_data();
        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_compact(&self.partner_signature)
            .map_err(|e| format!("Invalid partner signature format: {}", e))?;

        secp.verify_ecdsa(&msg, &sig, &partner_pubkey)
            .map_err(|e| format!("Partner signature verification failed: {}", e))
    }

    /// Verify the operator's signature over content + partner signature.
    pub fn verify_operator_signature(&self) -> Result<(), String> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, ecdsa::Signature};

        let secp = Secp256k1::new();
        let data = self.operator_signing_data();
        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_compact(&self.operator_signature)
            .map_err(|e| format!("Invalid operator signature format: {}", e))?;

        secp.verify_ecdsa(&msg, &sig, &self.operator_id)
            .map_err(|e| format!("Operator signature verification failed: {}", e))
    }

    /// Verify both signatures on this update.
    pub fn verify_signatures(&self) -> Result<(), String> {
        self.verify_partner_signature()?;
        self.verify_operator_signature()
    }

    /// Check if this update has valid (non-zero) signatures.
    pub fn is_fully_signed(&self) -> bool {
        self.partner_signature != [0u8; 64] && self.operator_signature != [0u8; 64]
    }

    /// Check if partner has signed (non-zero signature).
    pub fn has_partner_signature(&self) -> bool {
        self.partner_signature != [0u8; 64]
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
    /// Deposit public key (hex).
    pub pubkey: String,
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
            pubkey: hex::encode(d.pubkey.serialize()),
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
    /// Operator node ID.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_id: String,
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
    pub fn new(operator_id: PublicKey, reserves_id: String) -> Self {
        Self {
            operator_id,
            reserves_id,
            updates: Vec::new(),
            next_sequence: 0,
            pending_updates: HashMap::new(),
        }
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
        #[serde(with = "serde_pubkey")]
        deposit_pubkey: PublicKey,
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
    pub const ANNUALIZED_FIXED: u64 = 0;
    pub const ANNUALIZED_BPS: u64 = 2;
    pub const FREQUENCY_BLOCKS: u64 = 4;
}

impl TlvEncode for FeeStructure {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(fee_structure_fields::ANNUALIZED_FIXED, self.annualized_fixed)
            .u16_field(fee_structure_fields::ANNUALIZED_BPS, self.annualized_bps)
            .u32_field(fee_structure_fields::FREQUENCY_BLOCKS, self.frequency_blocks)
            .build()
    }
}

impl TlvDecode for FeeStructure {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            annualized_fixed: reader.read_u64(fee_structure_fields::ANNUALIZED_FIXED)?,
            annualized_bps: reader.read_u16(fee_structure_fields::ANNUALIZED_BPS)?,
            frequency_blocks: reader.read_u32(fee_structure_fields::FREQUENCY_BLOCKS)?,
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
            .pubkey_field(invoice_fields::ASSIGNED_DEPOSIT, &self.assigned_deposit)
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
            assigned_deposit: reader.read_pubkey(invoice_fields::ASSIGNED_DEPOSIT)?,
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
            .pubkey_field(pending_invoice_fields::ASSIGNED_DEPOSIT, &self.assigned_deposit)
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
            assigned_deposit: reader.read_pubkey(pending_invoice_fields::ASSIGNED_DEPOSIT)?,
            invoice_id: reader.read_string(pending_invoice_fields::INVOICE_ID)?,
            bolt11: reader.read_string(pending_invoice_fields::BOLT11)?,
        })
    }
}

// Field type constants for Deposit
mod deposit_fields {
    pub const PUBKEY: u64 = 0;
    pub const BALANCE: u64 = 2;
    pub const LOCKED_BALANCE: u64 = 4;
    pub const COLLATERAL_PLEDGE_AMOUNT: u64 = 12;
    pub const COLLATERAL_PLEDGE_EXPIRES: u64 = 14;
    pub const INVOICES: u64 = 6;
    pub const FEES: u64 = 8;
    pub const LAST_FEE_ASSESSMENT: u64 = 10;
}

impl TlvEncode for Deposit {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .pubkey_field(deposit_fields::PUBKEY, &self.pubkey)
            .u64_field(deposit_fields::BALANCE, self.balance)
            .u64_field(deposit_fields::LOCKED_BALANCE, self.locked_balance)
            .vec_field(deposit_fields::INVOICES, &self.invoices)
            .nested(deposit_fields::FEES, &self.fees)
            .u32_field(deposit_fields::LAST_FEE_ASSESSMENT, self.last_fee_assessment)
            .u64_field(deposit_fields::COLLATERAL_PLEDGE_AMOUNT, self.collateral_lock_amount)
            .u32_field(deposit_fields::COLLATERAL_PLEDGE_EXPIRES, self.collateral_lock_expires)
            .build()
    }
}

impl TlvDecode for Deposit {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            pubkey: reader.read_pubkey(deposit_fields::PUBKEY)?,
            balance: reader.read_u64(deposit_fields::BALANCE)?,
            locked_balance: reader.read_u64(deposit_fields::LOCKED_BALANCE)?,
            invoices: reader.read_vec(deposit_fields::INVOICES)?,
            fees: reader.read_nested(deposit_fields::FEES)?,
            last_fee_assessment: reader.read_u32(deposit_fields::LAST_FEE_ASSESSMENT)?,
            collateral_lock_amount: reader.read_u64_opt(deposit_fields::COLLATERAL_PLEDGE_AMOUNT)?.unwrap_or(0),
            collateral_lock_expires: reader.read_u32_opt(deposit_fields::COLLATERAL_PLEDGE_EXPIRES)?.unwrap_or(0),
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
    pub const RESERVES_ID: u64 = 6;
    pub const SEQUENCE_NUMBER: u64 = 8;
    pub const PREVIOUS_HASH: u64 = 10;
    pub const CURRENT_HASH: u64 = 12;
    pub const TIMESTAMP: u64 = 14;
    pub const PARTNER_SIGNATURE: u64 = 16;
    pub const OPERATOR_SIGNATURE: u64 = 18;
    pub const BLOCK_HEIGHT: u64 = 20;
    pub const BLOCK_HASH: u64 = 22;
}

impl TlvEncode for SignedLedgerUpdate {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .bytes_field(signed_update_fields::MESSAGE, &self.message)
            .u16_field(signed_update_fields::MESSAGE_TYPE, self.message_type)
            .pubkey_field(signed_update_fields::OPERATOR_ID, &self.operator_id)
            .string_field(signed_update_fields::RESERVES_ID, &self.reserves_id)
            .u64_field(signed_update_fields::SEQUENCE_NUMBER, self.sequence_number)
            .bytes_field(signed_update_fields::PREVIOUS_HASH, &self.previous_hash)
            .bytes_field(signed_update_fields::CURRENT_HASH, &self.current_hash)
            .u64_field(signed_update_fields::TIMESTAMP, self.timestamp)
            .u32_field(signed_update_fields::BLOCK_HEIGHT, self.block_height)
            .bytes_field(signed_update_fields::BLOCK_HASH, &self.block_hash)
            .bytes_field(signed_update_fields::PARTNER_SIGNATURE, &self.partner_signature)
            .bytes_field(signed_update_fields::OPERATOR_SIGNATURE, &self.operator_signature)
            .build()
    }
}

impl TlvDecode for SignedLedgerUpdate {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            message: reader.read_raw(signed_update_fields::MESSAGE)?.to_vec(),
            message_type: reader.read_u16(signed_update_fields::MESSAGE_TYPE)?,
            operator_id: reader.read_pubkey(signed_update_fields::OPERATOR_ID)?,
            reserves_id: reader.read_string(signed_update_fields::RESERVES_ID)?,
            sequence_number: reader.read_u64(signed_update_fields::SEQUENCE_NUMBER)?,
            previous_hash: reader.read_bytes(signed_update_fields::PREVIOUS_HASH)?,
            current_hash: reader.read_bytes(signed_update_fields::CURRENT_HASH)?,
            timestamp: reader.read_u64(signed_update_fields::TIMESTAMP)?,
            block_height: reader.read_u32_opt(signed_update_fields::BLOCK_HEIGHT)?.unwrap_or(0),
            block_hash: reader.read_bytes_opt(signed_update_fields::BLOCK_HASH)?.unwrap_or([0u8; 32]),
            partner_signature: reader.read_bytes(signed_update_fields::PARTNER_SIGNATURE)?,
            operator_signature: reader.read_bytes(signed_update_fields::OPERATOR_SIGNATURE)?,
        })
    }
}

// Field type constants for CollateralAttestation
mod collateral_attestation_fields {
    pub const OPERATOR_ID: u64 = 0;
    pub const QUORUM_MEMBER: u64 = 2;
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

    /// The reserves identifier (e.g., Bitcoin address for BDK, pubkey hex for LDK).
    pub reserves_id: String,

    /// The deposit pubkey (identifier for the deposit).
    #[serde(with = "serde_pubkey")]
    pub deposit_pubkey: PublicKey,

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
    /// Signs: "DEPOSIT_OFFER:{offer_id}:{operator}:{partner}:{deposit}:{address}:{max}:{min}:{deadline}"
    #[serde(with = "serde_64")]
    pub operator_signature: [u8; 64],
}

impl DepositOffer {
    /// Create the message to be signed for an offer.
    ///
    /// Returns the canonical message format that should be signed by the operator.
    pub fn signing_message(
        operator_id: &PublicKey,
        reserves_id: &str,
        deposit_pubkey: &PublicKey,
        funding_address: &str,
        max_amount_sats: u64,
        min_amount_sats: u64,
        deadline_block: u32,
    ) -> String {
        // Create a deterministic message that commits to all offer parameters
        format!(
            "DEPOSIT_OFFER:{}:{}:{}:{}:{}:{}:{}",
            hex::encode(operator_id.serialize()),
            reserves_id,
            hex::encode(deposit_pubkey.serialize()),
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        )
    }

    /// Compute the offer ID from the signing message.
    pub fn compute_offer_id(signing_message: &str) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash};
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
            &self.reserves_id,
            &self.deposit_pubkey,
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

    /// The deposit pubkey withdrawing funds.
    #[serde(with = "serde_pubkey")]
    pub deposit_pubkey: PublicKey,

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

    /// Depositor's signature authorizing the withdrawal.
    /// Signs: "WITHDRAWAL:{nonce}:{deposit}:{address}:{amount}:{fee}"
    #[serde(with = "serde_64")]
    pub depositor_signature: [u8; 64],
}

impl OnChainWithdrawal {
    /// Create the message to be signed for a withdrawal authorization.
    ///
    /// The nonce ensures each withdrawal request is unique, even if the
    /// same depositor requests the same amount to the same address twice.
    pub fn signing_message(
        nonce: &[u8; 32],
        deposit_pubkey: &PublicKey,
        destination_address: &str,
        amount_sats: u64,
        fee_sats: u64,
    ) -> String {
        format!(
            "WITHDRAWAL:{}:{}:{}:{}:{}",
            hex::encode(nonce),
            hex::encode(deposit_pubkey.serialize()),
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
        use bitcoin::hashes::{sha256, Hash};
        let hash = sha256::Hash::hash(signing_message.as_bytes());
        hash.to_byte_array()
    }

    /// Get the signing message for this withdrawal.
    pub fn get_signing_message(&self) -> String {
        Self::signing_message(
            &self.nonce,
            &self.deposit_pubkey,
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
        let mut deposit = Deposit::new(pk, None);

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
        let mut state = LedgerState::new(op, partner.to_string(), "tb1q...".to_string());

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
            reserves_id: pk.to_string(),
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            timestamp: 0,
            block_height: 0,
            block_hash: [0u8; 32],
            partner_signature: [0u8; 64],
            operator_signature: [0u8; 64],
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
            reserves_id: pk.to_string(),
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            timestamp: 1000,
            block_height: 0,
            block_hash: [0u8; 32],
            partner_signature: [0u8; 64],
            operator_signature: [0u8; 64],
        };

        // Test signing data generation
        let partner_data = update.partner_signing_data();
        assert!(!partner_data.is_empty());

        let operator_data = update.operator_signing_data();
        // Operator data includes partner_signature
        assert!(operator_data.len() > partner_data.len());
        assert_eq!(operator_data.len(), partner_data.len() + 64);

        // Test signature status checks
        assert!(!update.is_fully_signed());
        assert!(!update.has_partner_signature());
        assert!(!update.has_operator_signature());

        // Set non-zero signatures and check
        update.partner_signature = [0xaa; 64];
        assert!(update.has_partner_signature());
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
        let original = Invoice {
            id: "test-invoice-123".to_string(),
            payment_hash: [0xab; 32],
            amount: 100_000,
            expires: 1700000000,
            assigned_deposit: test_pubkey(),
            bolt11: "lnbc100n1...".to_string(),
        };
        let encoded = original.tlv_encode();
        let decoded = Invoice::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_pending_invoice_tlv_roundtrip() {
        let original = PendingInvoice {
            amount: 50_000,
            payment_hash: [0xcd; 32],
            expires: 1700001000,
            assigned_deposit: test_pubkey(),
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
        let original = Deposit {
            pubkey: pk,
            balance: 1_000_000,
            locked_balance: 50_000,
            invoices: vec![
                Invoice {
                    id: "inv1".to_string(),
                    payment_hash: [0x11; 32],
                    amount: 10_000,
                    expires: 1700000000,
                    assigned_deposit: pk,
                    bolt11: "lnbc10n1...".to_string(),
                },
            ],
            fees: FeeStructure::new(100, 25, 2016),
            last_fee_assessment: 800_000,
            collateral_lock_amount: 500_000,
            collateral_lock_expires: 850_000,
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
        let mut state = LedgerState::new(op, partner.to_string(), "tb1q...".to_string());

        // Add quorum members
        let collateral1 = test_pubkey_2();
        let collateral2 = test_pubkey_3();
        state.quorum_members = vec![collateral1, collateral2];

        // Add attestation for collateral1
        let attestation1 = CollateralAttestation::new(
            op,
            collateral1,
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
}
