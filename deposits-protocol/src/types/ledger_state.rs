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
    /// Reserves amount backing this ledger (millisatoshis).
    /// Set at LedgerOpen, updated at QuorumBegin during reserves rotation.
    #[serde(default)]
    pub reserves_amount: u64,
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
    /// Collateral attestations from quorum members proving their reserves.
    /// Key is the partner's public key (must be in quorum_members list).
    /// Attestations are updated periodically and validated before use.
    #[serde(with = "serde_pubkey_map", default)]
    pub collateral_attestations: HashMap<PublicKey, CollateralAttestation>,
    /// Pending conditional transfers between deposits.
    /// Key is the transfer_id (hash of the signing message).
    #[serde(with = "serde_transfer_id_map", default)]
    pub pending_transfers: HashMap<[u8; 32], PendingTransfer>,
    /// Open outbound invoice locks awaiting fulfill or fail.
    /// Key is the payment_id (payment hash). Populated by InvoiceLock,
    /// removed by InvoiceFulfill or InvoiceFail.
    #[serde(with = "serde_transfer_id_map", default)]
    pub open_invoice_locks: HashMap<[u8; 32], OpenInvoiceLock>,
    /// Payment hashes that have been credited (InvoiceCredit).
    /// Prevents double-crediting the same lightning payment.
    #[serde(default)]
    pub credited_payments: std::collections::HashSet<String>,
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
            collateral_attestations: HashMap::new(),
            pending_transfers: HashMap::new(),
            open_invoice_locks: HashMap::new(),
            credited_payments: std::collections::HashSet::new(),
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
            } => {
                next.operator_key = *operator_id;
                next.reserves_key = reserves_id.clone();
                next.genesis_block = *genesis_block;
                next.ledger_id = Self::compute_ledger_id(operator_id, reserves_id, *genesis_block);
                next.reserves_amount = *reserves_amount;
            }
            LedgerOperation::QuorumBegin {
                reserves_id,
                amount,
                total_collateral: _,
                quorum_expiry,
                ..
            } => {
                next.reserves_key = reserves_id.clone();
                next.reserves_amount = *amount;
                next.quorum_expiry = Some(*quorum_expiry);
                // Promote pending quorum members to active
                next.quorum_members = std::mem::take(&mut next.next_quorum_members);
                next.quorum_state = QuorumState::Active;
            }
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor,
                fees,
                transfer_fees,
                is_collateral,
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
                deposit.is_collateral = *is_collateral;
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
                deposit_id, amount, ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.lock(*amount)?;
            }
            LedgerOperation::OnchainFail { deposit_id, .. } => {
                let _deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                // TODO: Need to look up the withdrawal amount from withdrawal_id
            }
            LedgerOperation::OnchainFulfill {
                deposit_id, amount, ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.fulfill(*amount);
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
                }
            }
            LedgerOperation::QuorumAddMember {
                quorum_member,
                member_ledger_id,
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                collateral_lock_amount,
                collateral_lock_until,
                dispute_response_blocks,
                dispute_arm_blocks,
                service_response_blocks,
                max_transfer_timeout_blocks,
                max_descriptor_bytes,
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
                        collateral_lock_amount: *collateral_lock_amount,
                        collateral_lock_until: *collateral_lock_until,
                        dispute_response_blocks: *dispute_response_blocks,
                        dispute_arm_blocks: *dispute_arm_blocks,
                        service_response_blocks: *service_response_blocks,
                        max_transfer_timeout_blocks: *max_transfer_timeout_blocks,
                        max_descriptor_bytes: *max_descriptor_bytes,
                    });
                }
            }
            LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                next.quorum_members.retain(|m| m.pubkey != *quorum_member);
                next.next_quorum_members
                    .retain(|m| m.pubkey != *quorum_member);
                next.collateral_attestations.remove(quorum_member);
            }
            LedgerOperation::CollateralLock {
                deposit_id,
                amount,
                lock_until_block,
                for_ledger_id,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                if !deposit.is_collateral {
                    return Err(crate::DepositsError::InvalidState(
                        "CollateralLock can only be applied to collateral deposits".to_string(),
                    ));
                }
                // Update or insert per-ledger lock
                if let Some(entry) = deposit
                    .collateral_locks
                    .iter_mut()
                    .find(|e| e.for_ledger_id == *for_ledger_id)
                {
                    entry.amount = *amount;
                    entry.lock_until_block = *lock_until_block;
                } else {
                    // Check cap before adding new ledger
                    if deposit.collateral_locks.len() >= MAX_COLLATERAL_LOCKS {
                        return Err(crate::DepositsError::InvalidState(format!(
                            "Collateral deposit already backs {} ledgers (max {})",
                            deposit.collateral_locks.len(),
                            MAX_COLLATERAL_LOCKS
                        )));
                    }
                    deposit.collateral_locks.push(CollateralLockEntry {
                        for_ledger_id: for_ledger_id.clone(),
                        amount: *amount,
                        lock_until_block: *lock_until_block,
                    });
                }
                // Update legacy fields for backward compat (total across all locks)
                deposit.collateral_lock_amount =
                    deposit.collateral_locks.iter().map(|e| e.amount).sum();
                deposit.collateral_lock_expires = deposit
                    .collateral_locks
                    .iter()
                    .map(|e| e.lock_until_block)
                    .max()
                    .unwrap_or(0);
            }
            LedgerOperation::LedgerClose => {
                next.collateral_attestations.clear();
            }
            LedgerOperation::CollateralAttestation {
                collateral_operator,
                quorum_member,
                collateral_ledger_id,
                amount,
                block_height,
                lock_until_block,
                signature,
                ledger_hash,
            } => {
                let attestation = CollateralAttestation::new(
                    *collateral_operator,
                    *quorum_member,
                    collateral_ledger_id.clone(),
                    *amount,
                    *block_height,
                    *lock_until_block,
                    *signature,
                    *ledger_hash,
                );
                next.collateral_attestations
                    .insert(*collateral_operator, attestation);
            }
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
                next.collateral_attestations.clear();
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
                let total = amount + fee;
                if deposit.available_balance() < total {
                    return Err(crate::DepositsError::InsufficientDepositBalance {
                        available: deposit.available_balance(),
                        required: total,
                    });
                }
                deposit.balance = deposit.balance.saturating_sub(total);
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
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                    }
                    if let Some(dest) = next.deposits.get_mut(&pending.destination_deposit_id) {
                        dest.balance = dest.balance.saturating_add(pending.amount);
                    }
                }
            }
            LedgerOperation::TransferFail { transfer_id, .. } => {
                if let Some(pending) = next.pending_transfers.remove(transfer_id) {
                    let total = pending.total_locked();
                    if let Some(source) = next.deposits.get_mut(&pending.source_deposit_id) {
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                        source.balance = source.balance.saturating_add(total);
                    }
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
            LedgerOperation::CollateralLock {
                deposit_id,
                amount,
                lock_until_block,
                operator_id,
                witness,
                ..
            } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    let msg = crate::signature_utils::collateral_lock_signing_message(
                        deposit_id,
                        *amount,
                        *lock_until_block,
                        operator_id,
                    );
                    if !verifier.verify_witness(&deposit.descriptor, witness, &msg) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "CollateralLock",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
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
    pub fn total_deposit_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.balance).sum()
    }

    /// Get total balance of collateral deposits held by other operators on this ledger (msats).
    pub fn total_held_collateral(&self) -> u64 {
        self.deposits
            .values()
            .filter(|d| d.is_collateral)
            .map(|d| d.balance)
            .sum()
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(&self) -> u64 {
        self.deposits.values().map(|d| d.locked_balance).sum()
    }

    /// Check if reserves are sufficient.
    pub fn has_sufficient_reserves(&self) -> bool {
        self.reserves_amount >= self.total_deposit_balance()
    }

    /// Total attested collateral from all quorum members (millisatoshis).
    /// Computed from the collateral_attestations HashMap.
    pub fn total_collateral(&self) -> u64 {
        self.collateral_attestations
            .values()
            .map(|a| a.available_collateral())
            .sum()
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
            .filter(
                |member| match self.collateral_attestations.get(&member.pubkey) {
                    None => true,
                    Some(a) => !a.is_recent(current_block, max_age_blocks),
                },
            )
            .map(|m| m.pubkey)
            .collect()
    }

    /// Clear all collateral attestations.
    pub fn clear_collateral_attestations(&mut self) {
        self.collateral_attestations.clear();
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
