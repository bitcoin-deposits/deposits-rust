// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core type definitions for the Bitcoin Deposits Protocol.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use super::serde_helpers::*;

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
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
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
    ///
    /// Intermediate products are computed in u128 to prevent silent u64
    /// wrap-around. Realistic inputs overflow u64 easily: e.g. a ~$1M
    /// balance (≈10¹⁶ msats) × 100% bps (10_000) × a few thousand blocks
    /// exceeds 2⁶⁴ before the divisor rescues it. The final quotient fits
    /// in u64 for any sane balance, but we saturate the downcast
    /// defensively so a pathological input returns `u64::MAX` rather than
    /// wrapping to a small number.
    pub fn calculate_fee(&self, balance: u64, blocks_elapsed: u32) -> u64 {
        // Blocks per year (approximately)
        const BLOCKS_PER_YEAR: u128 = 52560; // 365.25 * 144

        let blocks = blocks_elapsed as u128;

        // Fixed fee portion (pro-rated for blocks elapsed)
        let fixed_fee = (self.annualized_msats as u128 * blocks) / BLOCKS_PER_YEAR;

        // Percentage fee portion (pro-rated)
        let bps_fee = (balance as u128 * self.annualized_bps as u128 * blocks)
            / (BLOCKS_PER_YEAR * 10_000);

        let total = fixed_fee + bps_fee;
        u64::try_from(total).unwrap_or(u64::MAX)
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
        Self {
            fixed_msats,
            rate_bps,
        }
    }

    /// Calculate the transfer fee for a given amount in msats.
    ///
    /// `amount_msats * rate_bps` can exceed u64 for large amounts — compute
    /// the proportional part in u128 and saturate the downcast.
    pub fn calculate_fee(&self, amount_msats: u64) -> u64 {
        let proportional = (amount_msats as u128 * self.rate_bps as u128) / 10_000;
        let proportional = u64::try_from(proportional).unwrap_or(u64::MAX);
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
/// An outbound Lightning invoice lock awaiting payment completion.
/// Tracked in LedgerState.open_invoice_locks so the operator can
/// resolve stuck locks by checking LDK payment status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenInvoiceLock {
    /// The deposit that funds are locked from.
    #[serde(with = "serde_deposit_id")]
    pub deposit_id: DepositId,
    /// Amount locked (millisatoshis).
    pub amount: u64,
    /// Sequence number of the InvoiceLock operation.
    pub lock_sequence: u64,
}

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

/// A pending on-chain withdrawal awaiting confirmation or failure.
///
/// Created by OnchainLock, resolved by OnchainFulfill (funds actually left
/// the reserves) or OnchainFail (withdrawal abandoned, lock released).
/// Tracked in `LedgerState.pending_withdrawals` keyed by `withdrawal_id`
/// so OnchainFail/OnchainFulfill can look up the locked amount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    /// The deposit the funds are locked from.
    #[serde(with = "serde_deposit_id")]
    pub deposit_id: DepositId,
    /// Amount being withdrawn (satoshis or msats, matching op field).
    pub amount: u64,
    /// On-chain miner fee allocated for this withdrawal.
    pub fee_sats: u64,
    /// Destination Bitcoin address.
    pub destination_address: String,
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
    /// Total obligation owed on this deposit, in millisatoshis.
    ///
    /// This is the authoritative figure counted toward the ledger's total
    /// obligations. It is not reduced when funds are locked for an in-flight
    /// operation — only on settlement (debit/fulfill).
    pub balance: u64,
    /// Portion of `balance` currently earmarked for in-flight operations
    /// (pending transfers, invoice locks), in millisatoshis.
    ///
    /// This is a subset of `balance`, not a separate bucket. Spendable funds
    /// are `available_balance() = balance - locked_balance`. Locking does not
    /// add to the ledger's total obligation because the funds are already
    /// counted in `balance`.
    pub locked_balance: u64,
    /// Outstanding unexpired invoices.
    pub invoices: Vec<Invoice>,
    /// Fee structure for this deposit.
    pub fees: FeeStructure,
    /// Block height of last fee assessment.
    pub last_fee_assessment: u32,
    /// Per-transfer fee schedule (fixed + proportional).
    #[serde(default)]
    pub transfer_fees: TransferFeeSchedule,
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
            transfer_fees: TransferFeeSchedule::default(),
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
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
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
    /// Block height until which the member commits to serving.
    /// Membership duration is limited to the shortest commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_until: Option<u32>,
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
    /// Basis points of *collected* fees that flow to this member as
    /// compensation for co-signing. Defaults to `DEFAULT_COMPENSATION_BPS`
    /// (~3%). For a Q=7 quorum with every member at the default, the operator
    /// distributes ~21% of fee revenue to cosigners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_bps: Option<u16>,
    /// Deposit on the operator's ledger where compensation lands. Identified
    /// by 16-byte DepositId; the deposit must already exist (the member opens
    /// it, or the operator opens it on the member's behalf, before this
    /// QuorumAddMember is appended).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_deposit_id: Option<DepositId>,
    /// Cadence at which accrued compensation is paid out, in blocks.
    /// Defaults to `DEFAULT_COMPENSATION_FREQUENCY_BLOCKS` (2016 ≈ 2 weeks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_frequency_blocks: Option<u32>,
}

/// Default compensation rate for a quorum member: 3% (300 bips) of collected
/// fees. Recommended when the member doesn't care to negotiate a custom rate.
pub const DEFAULT_COMPENSATION_BPS: u16 = 300;

/// Default compensation payout cadence: 2016 blocks (~2 weeks). Mirrors the
/// default `frequency_blocks` on `FeeStructure`, so by default a member is
/// paid once per operator fee-collection cycle.
pub const DEFAULT_COMPENSATION_FREQUENCY_BLOCKS: u32 = 2016;

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
///   │  - Only QuorumAddMember allowed
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
    /// No quorum yet. Operator-only signatures (no co-signing required).
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
    /// operations are allowed (along with DisputeArmed to transition).
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
                !matches!(operation_discriminant, 55..=57) // DisputeArmed, DisputeAcquire, DisputeYield
            }
            DisputeState::Disputed => {
                // Only QuorumAddMember and DisputeArmed allowed
                matches!(operation_discriminant, 43 | 57) // QuorumAddMember, DisputeArmed
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
    use bitcoin::hashes::{sha256, Hash};

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
