// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Ledger state definition and state transition logic.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::conformance::{ConformanceViolation, WitnessVerifier};
use super::core::*;
use super::serde_helpers::*;

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
    /// Reserves amount backing this ledger (deposit capacity, millisatoshis).
    /// Set at LedgerOpen, updated at QuorumBegin during reserves rotation.
    #[serde(default)]
    pub reserves_amount: u64,
    /// Collateral amount (security bond, millisatoshis).
    /// Set at LedgerOpen, updated at QuorumBegin. reserves + collateral = UTXO value.
    #[serde(default)]
    pub collateral_amount: u64,
    /// Quorum lifecycle state (PreQuorum → Active → Expired).
    /// Determines co-signature requirements and allowed operation types.
    #[serde(default)]
    pub quorum_state: QuorumState,
    /// Active quorum members (confirmed by QuorumBegin).
    /// These are the members whose co-signatures are required for operations.
    #[serde(default)]
    pub quorum_members: Vec<QuorumMember>,
    /// Next quorum members (added by QuorumAddMember, awaiting QuorumBegin).
    /// Promoted to quorum_members when QuorumBegin is applied.
    #[serde(default)]
    pub next_quorum_members: Vec<QuorumMember>,
    /// Block height when the current quorum expires (from QuorumBegin).
    #[serde(default)]
    pub quorum_expiry: Option<u32>,
    /// Pending conditional transfers between deposits.
    /// Key is the transfer_id (hash of the signing message).
    #[serde(with = "serde_transfer_id_map", default)]
    pub pending_transfers: HashMap<[u8; 32], PendingTransfer>,
    /// Open outbound invoice locks awaiting fulfill or fail.
    /// Key is the payment_id (payment hash). Populated by InvoiceLock,
    /// removed by InvoiceFulfill or InvoiceFail.
    #[serde(with = "serde_transfer_id_map", default)]
    pub open_invoice_locks: HashMap<[u8; 32], OpenInvoiceLock>,
    /// Pending on-chain withdrawals awaiting fulfill or fail.
    /// Key is the withdrawal_id. Populated by OnchainLock, removed by
    /// OnchainFulfill or OnchainFail. Stored so the resolving op (which
    /// only carries withdrawal_id) can recover the locked amount.
    #[serde(with = "serde_transfer_id_map", default)]
    pub pending_withdrawals: HashMap<[u8; 32], PendingWithdrawal>,
    /// Payment hashes that have been credited (InvoiceCredit).
    /// Prevents double-crediting the same lightning payment.
    #[serde(default)]
    pub credited_payments: std::collections::HashSet<String>,
    /// Running total of fees the operator has accrued on this ledger
    /// (msats), across both maintenance fees (FeeCollect) and per-transfer
    /// fees captured on TransferComplete. On-chain withdrawal fees are
    /// *not* included — those go to miners, not the operator.
    ///
    /// This is the substrate for quorum-member compensation payouts. It is
    /// monotonically non-decreasing; a future payout operation will be
    /// responsible for debiting it.
    #[serde(default)]
    pub fees_accumulated: u64,
    /// Current sequence number.
    pub sequence: u64,
    /// Hash chain tip — SHA256(prev_hash || update_message) for the latest update.
    #[serde(with = "serde_32", alias = "hash")]
    pub chain_tip_hash: [u8; 32],
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
    pub fn compute_ledger_id(
        operator_key: &PublicKey,
        reserves_key: &str,
        genesis_block: u32,
    ) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash};
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
            reserves_amount: 0,
            quorum_state: QuorumState::PreQuorum,
            quorum_members: Vec::new(),
            next_quorum_members: Vec::new(),
            quorum_expiry: None,
            collateral_amount: 0,
            pending_transfers: HashMap::new(),
            open_invoice_locks: HashMap::new(),
            pending_withdrawals: HashMap::new(),
            credited_payments: std::collections::HashSet::new(),
            fees_accumulated: 0,
            sequence: 0,
            chain_tip_hash: [0u8; 32],
            joined_quorums: Vec::new(),
            dispute_state: DisputeState::Normal,
            parent_pubkey: operator_key,
            quorum_at_fork: Vec::new(),
            dispute_fork_sequence: 0,
        }
    }

    /// Get the ledger_id as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    // ========================================================================
    // Immutable State Transition
    // ========================================================================

    /// Apply a ledger operation, returning a new state.
    ///
    /// This is a pure function: same state + same operation = same result.
    /// The original state is never mutated — callers replace it atomically:
    ///
    /// ```ignore
    /// self.state = self.state.apply(&operation)?;
    /// ```
    pub fn apply(
        &self,
        operation: &crate::messages::LedgerOperation,
    ) -> crate::DepositsResult<Self> {
        use crate::messages::LedgerOperation;

        let mut next = self.clone();
        match operation {
            LedgerOperation::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                reserves_amount,
                collateral_amount,
            } => {
                next.operator_key = *operator_id;
                next.reserves_key = reserves_id.clone();
                next.genesis_block = *genesis_block;
                next.ledger_id = Self::compute_ledger_id(operator_id, reserves_id, *genesis_block);
                next.reserves_amount = *reserves_amount;
                next.collateral_amount = *collateral_amount;
            }
            LedgerOperation::QuorumBegin {
                reserves_id,
                amount,
                collateral_amount,
                quorum_expiry,
                quorum_members,
                ..
            } => {
                next.reserves_key = reserves_id.clone();
                next.reserves_amount = *amount;
                next.collateral_amount = *collateral_amount;
                next.quorum_expiry = Some(*quorum_expiry);
                // Promote the subset of staged members that the operation
                // declared (validated upstream to be ⊆ next_quorum_members).
                // Members in next_quorum_members that the operation
                // *omitted* are dropped — they never enter the active set.
                let declared: std::collections::HashSet<_> =
                    quorum_members.iter().map(|m| m.pubkey).collect();
                let staged = std::mem::take(&mut next.next_quorum_members);
                next.quorum_members = staged
                    .into_iter()
                    .filter(|m| declared.contains(&m.pubkey))
                    .collect();
                next.quorum_state = QuorumState::Active;
            }
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor,
                fees,
                transfer_fees,
                receive_requires_sig,
                fee_change_after_blocks,
                fee_change_notice_blocks,
                fee_change_limit_bps,
                ..
            } => {
                if next.deposits.contains_key(deposit_id) {
                    return Err(crate::DepositsError::DepositAlreadyExists);
                }
                let mut deposit = Deposit::new(descriptor.clone(), fees.clone());
                if let Some(tf) = transfer_fees {
                    deposit.transfer_fees = tf.clone();
                }
                deposit.receive_requires_sig = *receive_requires_sig;
                deposit.fee_change_after_blocks = *fee_change_after_blocks;
                deposit.fee_change_notice_blocks = *fee_change_notice_blocks;
                deposit.fee_change_limit_bps = *fee_change_limit_bps;
                next.deposits.insert(*deposit_id, deposit);
            }
            LedgerOperation::DepositClose { deposit_id } => {
                let deposit = next
                    .deposits
                    .get(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                if deposit.balance > 0 {
                    return Err(crate::DepositsError::NonZeroBalance {
                        balance: deposit.balance,
                    });
                }
                next.deposits.remove(deposit_id);
            }
            LedgerOperation::FeeChange {
                deposit_id,
                new_fees,
                effective_block,
            } => {
                if let Some(deposit) = next.deposits.get_mut(deposit_id) {
                    deposit.pending_fee_change = Some((new_fees.clone(), *effective_block));
                }
            }
            LedgerOperation::DepositKeyRotate {
                deposit_id,
                new_descriptor,
                ..
            } => {
                if let Some(deposit) = next.deposits.get_mut(deposit_id) {
                    deposit.descriptor = new_descriptor.clone();
                }
            }
            LedgerOperation::InvoiceCredit {
                deposit_id,
                amount,
                payment_hash,
                ..
            } => {
                let hash_hex = hex::encode(payment_hash);
                if next.credited_payments.contains(&hash_hex) {
                    return Err(crate::DepositsError::ProtocolViolation {
                        violation_type: "duplicate_credit".to_string(),
                        details: format!("Payment {} already credited", &hash_hex[..16]),
                    });
                }
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.credit(*amount);
                next.credited_payments.insert(hash_hex);
            }
            LedgerOperation::InvoiceLock {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.lock(*amount)?;
                next.open_invoice_locks.insert(
                    *payment_id,
                    OpenInvoiceLock {
                        deposit_id: *deposit_id,
                        amount: *amount,
                        lock_sequence: *sequence_number,
                    },
                );
            }
            LedgerOperation::InvoiceFail {
                payment_id,
                deposit_id,
                amount,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.unlock(*amount);
                // Even on failure, the fixed portion of the transfer fee
                // applies (the variable portion is zero since no amount
                // moved). Charged best-effort from current balance —
                // saturating_sub guards the edge where balance dipped
                // below the fixed fee between lock and fail.
                let charged = deposit.transfer_fees.fixed_msats.min(deposit.balance);
                deposit.balance -= charged;
                next.fees_accumulated = next.fees_accumulated.saturating_add(charged);
                next.open_invoice_locks.remove(payment_id);
            }
            LedgerOperation::InvoiceFulfill {
                payment_id,
                deposit_id,
                amount,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.fulfill(*amount);
                next.open_invoice_locks.remove(payment_id);
            }
            LedgerOperation::OnchainCredit {
                deposit_id, amount, ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.credit(*amount);
            }
            LedgerOperation::OnchainLock {
                deposit_id,
                amount,
                fee_sats,
                destination_address,
                withdrawal_id,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                // Lock both the amount (leaves to destination) and the fee
                // (leaves to miners) — both actually leave the deposit when
                // the withdrawal confirms. Mirrors TransferLock, which locks
                // amount + fee. Saturating_add guards against astronomical
                // inputs from simulator paths.
                let total = amount.saturating_add(*fee_sats);
                deposit.lock(total)?;
                next.pending_withdrawals.insert(
                    *withdrawal_id,
                    PendingWithdrawal {
                        deposit_id: *deposit_id,
                        amount: *amount,
                        fee_sats: *fee_sats,
                        destination_address: destination_address.clone(),
                    },
                );
            }
            LedgerOperation::OnchainFail {
                withdrawal_id,
                deposit_id,
            } => {
                // Ensure the named deposit exists (mirrors prior behavior).
                next.deposits
                    .get(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                // Release the full lock (amount + fee_sats) recorded at
                // OnchainLock. The withdrawal didn't happen, so both the
                // amount and the reserved miner fee stay with the deposit.
                // If the withdrawal_id isn't tracked (e.g. replay on a state
                // that never saw the lock), silently ignore — mirrors the
                // TransferFail pattern of `if let Some(pending) = ...`.
                if let Some(pending) = next.pending_withdrawals.remove(withdrawal_id) {
                    if let Some(deposit) = next.deposits.get_mut(&pending.deposit_id) {
                        let total = pending.amount.saturating_add(pending.fee_sats);
                        deposit.unlock(total);
                        // Fixed operator fee applies even on failure;
                        // variable portion is zero. fee_sats was the miner
                        // fee, unrelated to operator revenue.
                        let charged = deposit.transfer_fees.fixed_msats.min(deposit.balance);
                        deposit.balance -= charged;
                        next.fees_accumulated = next.fees_accumulated.saturating_add(charged);
                    }
                }
            }
            LedgerOperation::OnchainFulfill {
                deposit_id,
                withdrawal_id,
                ..
            } => {
                // Ensure the named deposit exists (mirrors prior behavior).
                next.deposits
                    .get(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                // Fulfill using the total (amount + fee) recorded at
                // OnchainLock. Unlike TransferComplete where the fee is
                // operator income that stays on the ledger, an on-chain
                // fee goes to miners — so both amount and fee_sats actually
                // leave the deposit's obligation.
                if let Some(pending) = next.pending_withdrawals.remove(withdrawal_id) {
                    if let Some(deposit) = next.deposits.get_mut(&pending.deposit_id) {
                        let total = pending.amount.saturating_add(pending.fee_sats);
                        deposit.fulfill(total);
                    }
                }
            }
            LedgerOperation::FeeCollect {
                deposit_id,
                amount,
                block_height,
            } => {
                if let Some(deposit) = next.deposits.get_mut(deposit_id) {
                    if let Some((new_fees, effective)) = deposit.pending_fee_change.take() {
                        if *block_height >= effective {
                            deposit.fees = new_fees;
                        } else {
                            deposit.pending_fee_change = Some((new_fees, effective));
                        }
                    }
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                    deposit.last_fee_assessment = *block_height;
                    next.fees_accumulated = next.fees_accumulated.saturating_add(*amount);
                }
            }
            LedgerOperation::QuorumAddMember {
                quorum_member,
                member_ledger_id,
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                membership_until,
                dispute_response_blocks,
                dispute_arm_blocks,
                service_response_blocks,
                max_transfer_timeout_blocks,
                max_descriptor_bytes,
                compensation_bps,
                compensation_deposit_id,
                compensation_frequency_blocks,
                ..
            } => {
                let already_active = next
                    .quorum_members
                    .iter()
                    .any(|m| m.pubkey == *quorum_member);
                let already_pending = next
                    .next_quorum_members
                    .iter()
                    .any(|m| m.pubkey == *quorum_member);
                if !already_active && !already_pending {
                    next.next_quorum_members.push(QuorumMember {
                        pubkey: *quorum_member,
                        ledger_id: member_ledger_id.clone(),
                        min_fee_bps: *min_fee_bps,
                        min_fee_fixed: *min_fee_fixed,
                        max_fee_period: *max_fee_period,
                        membership_until: *membership_until,
                        dispute_response_blocks: *dispute_response_blocks,
                        dispute_arm_blocks: *dispute_arm_blocks,
                        service_response_blocks: *service_response_blocks,
                        max_transfer_timeout_blocks: *max_transfer_timeout_blocks,
                        max_descriptor_bytes: *max_descriptor_bytes,
                        compensation_bps: *compensation_bps,
                        compensation_deposit_id: *compensation_deposit_id,
                        compensation_frequency_blocks: *compensation_frequency_blocks,
                    });
                }
            }
            LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                // Unstage only. The active set (`quorum_members`) reflects
                // the on-chain UTXO's signers; mutating it without an
                // accompanying rotation tx would silently break custody —
                // the on-chain script still requires those keys to spend.
                // Membership in the *active* set leaves only via QuorumBegin
                // (rotation re-declares membership) or QuorumLeave.
                next.next_quorum_members
                    .retain(|m| m.pubkey != *quorum_member);
            }
            LedgerOperation::LedgerClose => {}
            LedgerOperation::QuorumJoin {
                operator_id,
                ledger_id,
                membership_expires,
            } => {
                if let Some(existing) = next
                    .joined_quorums
                    .iter_mut()
                    .find(|m| m.operator_id == *operator_id && m.ledger_id == *ledger_id)
                {
                    existing.membership_expires = *membership_expires;
                } else {
                    next.joined_quorums.push(QuorumMembership {
                        operator_id: *operator_id,
                        ledger_id: ledger_id.clone(),
                        membership_expires: *membership_expires,
                        joined_at_sequence: next.sequence + 1,
                    });
                }
            }
            LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            } => {
                next.quorum_at_fork = next.quorum_members.clone();
                next.dispute_fork_sequence = *last_valid_sequence;
                next.dispute_state = DisputeState::Disputed;
            }
            LedgerOperation::DisputeArmed { .. } => {
                next.dispute_state = DisputeState::Armed;
            }
            LedgerOperation::DisputeAcquire { new_custodian, .. } => {
                next.operator_key = *new_custodian;
                next.parent_pubkey = *new_custodian;
                next.dispute_state = DisputeState::Normal;
                next.quorum_at_fork.clear();
                next.dispute_fork_sequence = 0;
            }
            LedgerOperation::DisputeYield => {
                next.dispute_state = DisputeState::Tombstoned;
            }
            LedgerOperation::TransferLock {
                nonce,
                source_deposit_id,
                destination_deposit_id,
                amount,
                fee,
                completion_script,
                timeout_height,
                transfer_id,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(source_deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                let total = amount.saturating_add(*fee);
                if deposit.available_balance() < total {
                    return Err(crate::DepositsError::InsufficientDepositBalance {
                        available: deposit.available_balance(),
                        required: total,
                    });
                }
                // `balance` is the total obligation for this deposit (includes
                // any locked portion). TransferLock just marks more of that
                // balance as locked — it does NOT reduce the obligation.
                deposit.locked_balance = deposit.locked_balance.saturating_add(total);
                next.pending_transfers.insert(
                    *transfer_id,
                    PendingTransfer {
                        transfer_id: *transfer_id,
                        nonce: *nonce,
                        source_deposit_id: *source_deposit_id,
                        destination_deposit_id: *destination_deposit_id,
                        amount: *amount,
                        fee: *fee,
                        completion_script: completion_script.clone(),
                        timeout_height: *timeout_height,
                    },
                );
            }
            LedgerOperation::TransferComplete { transfer_id, .. } => {
                if let Some(pending) = next.pending_transfers.remove(transfer_id) {
                    let total = pending.total_locked();
                    if let Some(source) = next.deposits.get_mut(&pending.source_deposit_id) {
                        // Lock released; amount actually left the source.
                        // Fee is operator income (not tracked as per-deposit
                        // obligation), so only `amount` comes off source.balance.
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                        source.balance = source.balance.saturating_sub(pending.amount);
                    }
                    if let Some(dest) = next.deposits.get_mut(&pending.destination_deposit_id) {
                        dest.balance = dest.balance.saturating_add(pending.amount);
                    }
                    // The transfer fee is operator income — tally it for later
                    // distribution to quorum members (see QuorumMember.compensation_*).
                    next.fees_accumulated = next.fees_accumulated.saturating_add(pending.fee);
                }
            }
            LedgerOperation::TransferFail { transfer_id, .. } => {
                if let Some(pending) = next.pending_transfers.remove(transfer_id) {
                    let total = pending.total_locked();
                    let mut charged = 0u64;
                    if let Some(source) = next.deposits.get_mut(&pending.source_deposit_id) {
                        // Lock released — the amount + proportional fee are
                        // refunded to the depositor. The fixed portion of
                        // the fee still applies, since the operator did
                        // real work holding the lock; the variable portion
                        // is zero because no amount moved. Read from the
                        // deposit's current schedule — sufficient for v1.
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                        charged = source.transfer_fees.fixed_msats.min(source.balance);
                        source.balance -= charged;
                    }
                    next.fees_accumulated = next.fees_accumulated.saturating_add(charged);
                }
            }
            LedgerOperation::DeliveryEmbed { .. } => {
                // No state changes — causal ordering only.
            }
        }
        Ok(next)
    }

    /// Apply an operation and check conformance using the given verifier.
    ///
    /// Returns the new state and any conformance violations. The state is
    /// always returned (even if non-conforming) so watchers can track
    /// misbehaving operators.
    pub fn apply_with_verifier(
        &self,
        operation: &crate::messages::LedgerOperation,
        verifier: &impl WitnessVerifier,
    ) -> crate::DepositsResult<(Self, Vec<ConformanceViolation>)> {
        let next = self.apply(operation)?;
        let violations = next.check_conformance(operation, Some(self), verifier);
        Ok((next, violations))
    }

    /// Apply an operation, returning an error if the result is non-conforming.
    ///
    /// Use this for the operator's own operations — it refuses to produce
    /// a non-conforming ledger state.
    pub fn check_and_apply(
        &self,
        operation: &crate::messages::LedgerOperation,
        verifier: &impl WitnessVerifier,
    ) -> crate::DepositsResult<Self> {
        let (next, violations) = self.apply_with_verifier(operation, verifier)?;
        if let Some(v) = violations.first() {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "conformance".to_string(),
                details: v.to_string(),
            });
        }
        Ok(next)
    }

    /// Check the conformance of this state after an operation was applied.
    ///
    /// `pre_state` is the state before apply() — needed for DepositKeyRotate
    /// where the witness must satisfy the old descriptor. Pass `None` to skip
    /// pre-state-dependent checks.
    ///
    /// Returns an empty vec if the state is conforming.
    pub fn check_conformance(
        &self,
        operation: &crate::messages::LedgerOperation,
        pre_state: Option<&LedgerState>,
        verifier: &impl WitnessVerifier,
    ) -> Vec<ConformanceViolation> {
        use crate::messages::LedgerOperation;

        let mut violations = Vec::new();

        // Reserve sufficiency: after any credit, total deposits must not exceed reserves.
        match operation {
            LedgerOperation::InvoiceCredit { .. }
            | LedgerOperation::OnchainCredit { .. }
            | LedgerOperation::TransferComplete { .. } => {
                let obligations = self.total_deposit_balance();
                if self.reserves_amount < obligations {
                    violations.push(ConformanceViolation::InsufficientReserves {
                        reserves: self.reserves_amount,
                        obligations,
                    });
                }
            }
            _ => {}
        }

        // Witness verification for operations that carry authorization proofs.
        match operation {
            LedgerOperation::InvoiceLock {
                deposit_id,
                amount,
                payment_id,
                witness,
                ..
            } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    let msg = crate::signature_utils::invoice_lock_signing_message(
                        deposit_id, payment_id, *amount,
                    );
                    if !verifier.verify_witness(&deposit.descriptor, witness, &msg) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "InvoiceLock",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
            }
            LedgerOperation::InvoiceFulfill {
                deposit_id,
                amount,
                payment_id,
                witness,
                preimage,
                ..
            } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    let msg = crate::signature_utils::invoice_lock_signing_message(
                        deposit_id, payment_id, *amount,
                    );
                    if !verifier.verify_witness(&deposit.descriptor, witness, &msg) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "InvoiceFulfill",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
                // Verify preimage matches payment_id (which is the payment hash)
                let hash = sha256::Hash::hash(preimage).to_byte_array();
                if hash != *payment_id {
                    violations.push(ConformanceViolation::InvalidWitness {
                        operation: "InvoiceFulfill",
                        detail: "preimage does not match payment hash".to_string(),
                    });
                }
            }
            LedgerOperation::OnchainLock {
                deposit_id,
                amount,
                fee_sats,
                destination_address,
                withdrawal_id,
                witness,
            } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    let msg = crate::signature_utils::withdrawal_signing_message(
                        withdrawal_id,
                        deposit_id,
                        destination_address,
                        *amount,
                        *fee_sats,
                    );
                    if !verifier.verify_witness(&deposit.descriptor, witness, &msg) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "OnchainLock",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
            }
            LedgerOperation::TransferLock {
                nonce,
                source_deposit_id,
                destination_deposit_id,
                amount,
                fee,
                completion_script,
                timeout_height,
                witness,
                ..
            } => {
                // Look up descriptor from the state BEFORE this operation was applied.
                // Since apply() already consumed the balance, we check against current state
                // where the deposit still exists.
                if let Some(deposit) = self.deposits.get(source_deposit_id) {
                    let msg = crate::signature_utils::transfer_lock_signing_message(
                        nonce,
                        source_deposit_id,
                        destination_deposit_id,
                        *amount,
                        *fee,
                        completion_script,
                        *timeout_height,
                    );
                    if !verifier.verify_witness(&deposit.descriptor, witness, &msg) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "TransferLock",
                            detail: "witness does not satisfy source deposit descriptor"
                                .to_string(),
                        });
                    }
                }
            }
            LedgerOperation::DepositKeyRotate {
                deposit_id,
                new_descriptor,
                witness,
            } => {
                // The witness must satisfy the OLD descriptor (proving authorization to rotate).
                // apply() already updated the descriptor, so we use pre_state to get the old one.
                if let Some(pre) = pre_state {
                    if let Some(old_deposit) = pre.deposits.get(deposit_id) {
                        // Message is SHA256(new_descriptor)
                        let msg = sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();
                        if !verifier.verify_witness(&old_deposit.descriptor, witness, &msg) {
                            violations.push(ConformanceViolation::InvalidWitness {
                                operation: "DepositKeyRotate",
                                detail: "witness does not satisfy old deposit descriptor"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        violations
    }

    /// Get total balance across all deposits (millisatoshis).
    ///
    /// This is the operator's total obligation. Per the design, `balance`
    /// already represents the total claim for each deposit (including any
    /// portion currently locked for in-flight ops). Per-deposit spendable
    /// funds are computed by `available_balance()` = `balance - locked_balance`.
    pub fn total_deposit_balance(&self) -> u64 {
        self.deposits
            .values()
            .fold(0u64, |acc, d| acc.saturating_add(d.balance))
    }

    /// Get the declared collateral amount for this ledger (msats).
    pub fn total_collateral(&self) -> u64 {
        self.collateral_amount
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.locked_balance).sum()
    }

    /// Check if reserves are sufficient.
    pub fn has_sufficient_reserves(&self) -> bool {
        self.reserves_amount >= self.total_deposit_balance()
    }

    /// Get active quorum memberships (not expired).
    ///
    /// Returns references to memberships where `membership_expires > current_block`.
    pub fn active_quorum_memberships(&self, current_block: u32) -> Vec<&QuorumMembership> {
        self.joined_quorums
            .iter()
            .filter(|m| m.membership_expires > current_block)
            .collect()
    }
}
