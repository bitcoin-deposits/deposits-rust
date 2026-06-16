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

use super::conformance::ConformanceViolation;
use super::core::*;
use super::serde_helpers::*;

/// Serde default for `LedgerState::active_ruleset_name`. Pins to
/// `"legacy"` so existing on-disk ledgers (no `active_ruleset_name`
/// in their persisted JSON) deserialize to the legacy ruleset —
/// matches the on-chain shape they were built under.
fn default_ruleset_name() -> String {
    "legacy".to_string()
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
    ///
    /// `im::OrdMap` (persistent B-tree): `clone()` is O(1) structural sharing,
    /// so the per-op `LedgerState` clone on speculative/verify/re-import paths
    /// doesn't copy the whole map. Mutation is O(log n) copy-on-write.
    #[serde(with = "serde_deposit_id_map")]
    pub deposits: im::OrdMap<DepositId, Deposit>,
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
    /// Protocol-ruleset name this ledger is currently governed by.
    /// Set from `QuorumBegin.protocol_version`; missing field
    /// (legacy QuorumBegins) resolves to `"legacy"` via
    /// `crate::ruleset::resolve_or_legacy` — that's the on-chain
    /// shape every pre-versioned ledger has.
    #[serde(default = "default_ruleset_name")]
    pub active_ruleset_name: String,
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
    ///
    /// Append-only (a hash goes in at credit time and is never removed), so an
    /// `im::OrdSet` (persistent B-tree) is the natural fit: clone shares all
    /// prior entries O(1); each credit adds a version pointing at the old. This
    /// set grows one-per-payment and was the dominant per-op clone cost.
    #[serde(default)]
    pub credited_payments: im::OrdSet<String>,
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
            deposits: im::OrdMap::new(),
            reserves_amount: 0,
            quorum_state: QuorumState::PreQuorum,
            quorum_members: Vec::new(),
            next_quorum_members: Vec::new(),
            quorum_expiry: None,
            active_ruleset_name: default_ruleset_name(),
            collateral_amount: 0,
            pending_transfers: HashMap::new(),
            open_invoice_locks: HashMap::new(),
            pending_withdrawals: HashMap::new(),
            credited_payments: im::OrdSet::new(),
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

    /// State-machine primitive: apply a ledger operation against this
    /// state, returning the next state. **No cryptographic validation.**
    /// The caller is responsible for ensuring the operation has been
    /// blessed (operator signature + cosig threshold) — typically by
    /// going through [`apply_signed`] or [`check_speculative`] instead.
    ///
    /// Pure: same state + same operation = same result. The original
    /// state is never mutated — callers replace it atomically:
    ///
    /// ```ignore
    /// self.state = self.state.apply(&operation)?;
    /// ```
    ///
    /// Use this directly only for:
    /// - load-time replay paths where the data is presumed-valid (e.g.
    ///   re-hydrating from a trusted jsonl);
    /// - speculative inspection ("what would the state look like if
    ///   this op were applied?") with no intent to advance the canonical
    ///   chain;
    /// - test scaffolding that builds states bypassing the signing flow.
    ///
    /// Production write paths use [`apply_signed`].
    ///
    /// [`apply_signed`]: Self::apply_signed
    /// [`check_speculative`]: Self::check_speculative
    /// Functional apply: returns a new state, leaving `self` untouched — the
    /// ergonomic form for callers that need before+after (conformance verifier,
    /// speculative checks, tests). One full clone per call, fine off the hot
    /// path. Per-history-op loops (append, replay) should use `apply_in_place`
    /// to stay O(1)/op instead of O(n)/op (the O(n) vs O(n^2) ledger question).
    pub fn apply(
        &self,
        operation: &crate::messages::LedgerOperation,
    ) -> crate::DepositsResult<Self> {
        let mut next = self.clone();
        next.apply_in_place(operation)?;
        Ok(next)
    }

    /// In-place apply — the actual state machine. Mutates `self` directly so the
    /// growing state isn't cloned on every operation; this is what keeps
    /// building/replaying a large ledger O(n) rather than O(n^2). Single ops
    /// validate before they mutate, so an early `?` leaves state untouched;
    /// Batch keeps all-or-nothing semantics via a scratch copy.
    pub fn apply_in_place(
        &mut self,
        operation: &crate::messages::LedgerOperation,
    ) -> crate::DepositsResult<()> {
        use crate::messages::LedgerOperation;

        let next = &mut *self;
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
                protocol_version,
                ..
            } => {
                let chosen_ruleset = protocol_version
                    .clone()
                    .unwrap_or_else(default_ruleset_name);

                // Promote the subset of staged members that the operation
                // declared (validated upstream to be ⊆ next_quorum_members).
                // Members in next_quorum_members that the operation
                // *omitted* are dropped — they never enter the active set.
                let declared: std::collections::HashSet<_> =
                    quorum_members.iter().map(|m| m.pubkey).collect();
                let staged = std::mem::take(&mut next.next_quorum_members);
                let promoted: Vec<QuorumMember> = staged
                    .into_iter()
                    .filter(|m| declared.contains(&m.pubkey))
                    .collect();

                // Ruleset attestation gate. Skipped for "legacy" so
                // pre-Q1 chains (every QuorumAddMember has empty
                // `supported_rulesets`) still validate; for any other
                // ruleset, every promoted member must have signed a
                // `QuorumMemberResponse` declaring support, otherwise
                // we have no proof this member can validate the rules
                // we're about to commit to. Caught here in `apply` so
                // every node that replays the chain enforces it, not
                // just the rotating operator.
                if chosen_ruleset != default_ruleset_name() {
                    let unsupported: Vec<String> = promoted
                        .iter()
                        .filter(|m| {
                            !m.supported_rulesets.iter().any(|s| s == &chosen_ruleset)
                        })
                        .map(|m| hex::encode(m.pubkey.serialize()))
                        .collect();
                    if !unsupported.is_empty() {
                        return Err(crate::DepositsError::ProtocolViolation {
                            violation_type: "ruleset_unsupported_by_member".to_string(),
                            details: format!(
                                "QuorumBegin pinned to ruleset '{}' but {} member(s) did not declare support: {}",
                                chosen_ruleset,
                                unsupported.len(),
                                unsupported.join(", ")
                            ),
                        });
                    }
                }

                next.reserves_key = reserves_id.clone();
                next.reserves_amount = *amount;
                next.collateral_amount = *collateral_amount;
                next.quorum_expiry = Some(*quorum_expiry);
                next.active_ruleset_name = chosen_ruleset;
                next.quorum_members = promoted;
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
                nonce,
                expiry,
                ..
            } => {
                if let Some(deposit) = next.deposits.get_mut(deposit_id) {
                    deposit.descriptor = new_descriptor.clone();
                    deposit.seen_nonces.insert((*nonce, *expiry));
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
                nonce,
                expiry,
                witness,
                ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.lock(*amount)?;
                deposit.seen_nonces.insert((*nonce, *expiry));
                // Cache the depositor's witness on the open lock so the
                // eventual InvoiceFulfill (committed asynchronously by
                // the background payment-completion task once LDK
                // reports the payment settled) can re-attach it. The
                // conformance verifier requires every InvoiceFulfill
                // carry a witness valid against the deposit's descriptor,
                // and only the depositor can produce one — caching it
                // at lock time is what lets the operator commit a
                // valid Fulfill without round-tripping back to the
                // wallet.
                next.open_invoice_locks.insert(
                    *payment_id,
                    OpenInvoiceLock {
                        deposit_id: *deposit_id,
                        amount: *amount,
                        lock_sequence: *sequence_number,
                        witness: witness.clone(),
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
                nonce,
                expiry,
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
                deposit.seen_nonces.insert((*nonce, *expiry));
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
                member_response,
                ..
            } => {
                let supported_rulesets = match member_response.as_deref() {
                    Some(blob) => {
                        // Trust the decoded list verbatim. Signature +
                        // loose-vs-blob equality were already checked by
                        // `validate_quorum_add_member_blob` upstream;
                        // by the time we apply here, the blob is
                        // authoritative.
                        use crate::tlv::TlvDecode;
                        crate::types::QuorumMemberResponse::tlv_decode(blob)
                            .map(|r| r.supported_rulesets)
                            .unwrap_or_default()
                    }
                    // Legacy QuorumAddMember without a blob: leave
                    // empty. `quorum begin` treats empty as "unknown"
                    // and assumes legacy-only support.
                    None => Vec::new(),
                };
                let staged = QuorumMember {
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
                    supported_rulesets,
                };
                // Upsert into next_quorum_members. Re-staging an existing
                // entry (whether it's currently active or already pending)
                // overwrites with the new terms — that's how refresh
                // extends `membership_until`. The active set is never
                // touched here; QuorumBegin promotes from next_quorum_members.
                if let Some(existing) = next
                    .next_quorum_members
                    .iter_mut()
                    .find(|m| m.pubkey == *quorum_member)
                {
                    *existing = staged;
                } else {
                    next.next_quorum_members.push(staged);
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
                transfer_nonce,
                source_deposit_id,
                destination_deposit_id,
                amount,
                fee,
                completion_script,
                timeout_height,
                transfer_id,
                nonce,
                expiry,
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
                deposit.seen_nonces.insert((*nonce, *expiry));
                next.pending_transfers.insert(
                    *transfer_id,
                    PendingTransfer {
                        transfer_id: *transfer_id,
                        nonce: *transfer_nonce,
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
            LedgerOperation::Batch(ops) => {
                // Transactional: build on a scratch copy, commit only on full
                // success. If any inner op fails, `?` returns Err and the
                // scratch is dropped — `*next` (i.e. `self`) is untouched, so
                // failure leaves the original state intact. Now that apply
                // mutates in place we can't replay onto `self` directly without
                // losing that atomicity, hence the explicit scratch (one clone
                // per Batch op, not per inner op — and Batches are rare).
                //
                // Validation (empty/oversize/nested-Batch) happens in
                // `validate_operation`; by the time we get here every inner op
                // is structurally permitted.
                let mut scratch = next.clone();
                for inner in ops {
                    scratch.apply_in_place(inner)?;
                }
                *next = scratch;
            }
        }
        Ok(())
    }

    /// Apply an operation and check conformance.
    ///
    /// Returns the new state and any conformance violations. The state is
    /// always returned (even if non-conforming) so watchers can track
    /// misbehaving operators. `current_height` drives the expiry check
    /// (`op.expiry < current_height` is rejected) and the seen_nonces GC
    /// (entries whose `expiry < current_height` are dropped before the
    /// uniqueness check).
    pub fn apply_with_verifier(
        &self,
        operation: &crate::messages::LedgerOperation,
        authorizer: &impl crate::types::Authorizer,
        current_height: u32,
    ) -> crate::DepositsResult<(Self, Vec<ConformanceViolation>)> {
        let next = self.apply(operation)?;
        let violations =
            next.check_conformance(operation, Some(self), authorizer, current_height);
        Ok((next, violations))
    }

    /// The canonical way to advance a `LedgerState`: verify that
    /// `update` carries the threshold of cryptographic blessings the
    /// protocol requires, then apply the embedded operation through
    /// the state machine + conformance pipeline.
    ///
    /// Invariant: every `LedgerState` reachable through this method has
    /// been blessed by (a) the current chain's signing key
    /// (`parent_pubkey`) and (b) — once `quorum_members` is non-empty —
    /// a majority of the active quorum. Callers may chain transitions
    /// purely through this method and trust the resulting state without
    /// re-checking sigs downstream.
    ///
    /// Checks (in order; first failure short-circuits):
    /// 1. Sequence: `update.sequence_number == self.sequence + 1` for
    ///    non-genesis; `== 0` for the LedgerOpen path (when invoked on
    ///    a fresh state where `self.sequence == 0` and chain_tip_hash
    ///    is all-zero).
    /// 2. Chain continuity: `update.previous_hash == self.chain_tip_hash`.
    /// 3. Custody: `update.operator_id == self.parent_pubkey`. After a
    ///    `DisputeAcquire` apply mutates `parent_pubkey`, subsequent
    ///    updates from the new custodian pass naturally.
    /// 4. Content integrity: `update.content_hash == update.compute_hash()`.
    /// 5. Operator BIP-340 Schnorr signature over `content_hash` by
    ///    `operator_id` (delegated to `update.verify_operator_signature()`).
    /// 6. Cosig threshold: when `self.quorum_members` is non-empty (or
    ///    `self.next_quorum_members` for the first `QuorumBegin`),
    ///    `update.cosignatures` must hold valid sigs from a majority
    ///    of distinct members of that set. (Legacy single-cosig form
    ///    accepted when `cosignatures` is empty.)
    /// 7. State machine apply + conformance (`check_and_apply`). For
    ///    a seq-0 `LedgerOpen` the LedgerState's pre-apply identity
    ///    fields (operator_key, reserves_key, genesis_block) are
    ///    overwritten by the operation; we additionally check that
    ///    `update.ledger_id == LedgerState::derive_id(...)` so a writer
    ///    can't publish under a `#d` tag that doesn't match their
    ///    declared operator+reserves+genesis_block tuple.
    pub fn apply_signed(
        &self,
        update: &crate::types::SignedLedgerUpdate,
        authorizer: &impl crate::types::Authorizer,
    ) -> crate::DepositsResult<Self> {
        use crate::messages::LedgerOperation;
        use crate::tlv::TlvDecode;

        // 1. Sequence.
        let expected_seq = if self.chain_tip_hash == [0u8; 32] && self.sequence == 0 {
            0 // genesis
        } else {
            self.sequence + 1
        };
        if update.sequence_number != expected_seq {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "sequence_mismatch".to_string(),
                details: format!(
                    "update.sequence_number {} ≠ expected {}",
                    update.sequence_number, expected_seq,
                ),
            });
        }

        // 2. Chain continuity.
        if update.previous_hash != self.chain_tip_hash {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "previous_hash_mismatch".to_string(),
                details: format!(
                    "update.previous_hash {} ≠ chain_tip_hash {}",
                    hex::encode(update.previous_hash),
                    hex::encode(self.chain_tip_hash),
                ),
            });
        }

        // 3. Custody. Genesis exempted because `self.parent_pubkey`
        //    isn't yet meaningful — the LedgerOpen establishes it.
        if update.sequence_number != 0 && update.operator_id != self.parent_pubkey {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "operator_id_mismatch".to_string(),
                details: format!(
                    "update.operator_id {} ≠ chain's current signer {}",
                    update.operator_id, self.parent_pubkey,
                ),
            });
        }

        // 4. Content integrity. Without this, a writer could publish a
        //    SignedLedgerUpdate whose `content_hash` doesn't match its
        //    `message` body — the operator_signature would verify but
        //    the message we'd actually apply isn't what the operator
        //    committed to.
        if update.content_hash != update.compute_hash() {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "content_hash_mismatch".to_string(),
                details: "content_hash doesn't match compute_hash(update)".to_string(),
            });
        }

        // 5. Operator signature. Delegated to `SignedLedgerUpdate::
        //    verify_operator_signature()`, which encodes the canonical
        //    digest (`SHA256(operator_signing_data())`) used by every
        //    production signing path (`Node::sign_last_update` in
        //    deposits-node/src/node/init.rs:406).
        if let Err(e) = update.verify_operator_signature() {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "bad_operator_signature".to_string(),
                details: e,
            });
        }

        // 6. Cosig threshold per DEP-05 §Lifecycle (and DEP-02
        //    §Cosignatures). Empty active quorum → genesis or
        //    pre-QuorumBegin updates; no cosigs required. For the
        //    first QuorumBegin specifically, the quorum is staged in
        //    `next_quorum_members` (not yet promoted) — accept cosigs
        //    from that set. The required threshold comes from
        //    `cosign_threshold::cosign_requirement` so the lifecycle
        //    cascade (majority → minority → single → operator-alone
        //    past quorum_expiry, for establishment ops only) is
        //    applied uniformly. Delegates signature verification to
        //    `SignedLedgerUpdate::verify_cosign_signatures`.
        let cosig_set: Vec<bitcoin::secp256k1::PublicKey> = if !self.quorum_members.is_empty() {
            self.quorum_members.iter().map(|m| m.pubkey).collect()
        } else if matches!(
            LedgerOperation::tlv_decode(&update.message),
            Ok(LedgerOperation::QuorumBegin { .. })
        ) {
            self.next_quorum_members.iter().map(|m| m.pubkey).collect()
        } else {
            Vec::new()
        };
        if !cosig_set.is_empty() {
            let op = LedgerOperation::tlv_decode(&update.message).map_err(|e| {
                crate::DepositsError::ProtocolViolation {
                    violation_type: "bad_operation_payload".to_string(),
                    details: format!("decode operation for threshold check: {:?}", e),
                }
            })?;
            let req = crate::cosign_threshold::cosign_requirement(self, &op, update.block_height);
            if !req.allowed {
                return Err(crate::DepositsError::ProtocolViolation {
                    violation_type: "uncosignable_op_at_tier".to_string(),
                    details: req.reason,
                });
            }
            if !req.operator_alone {
                if let Err(e) = update.verify_cosign_signatures(&cosig_set, req.required_sigs) {
                    return Err(crate::DepositsError::ProtocolViolation {
                        violation_type: "insufficient_cosignatures".to_string(),
                        details: e,
                    });
                }
            }
        }

        // 7. ledger_id derivation for seq-0 LedgerOpen.
        if update.sequence_number == 0 {
            if let Ok(LedgerOperation::LedgerOpen {
                reserves_id,
                genesis_block,
                ..
            }) = LedgerOperation::tlv_decode(&update.message)
            {
                let derived = Self::compute_ledger_id(&update.operator_id, &reserves_id, genesis_block);
                if derived != update.ledger_id {
                    return Err(crate::DepositsError::ProtocolViolation {
                        violation_type: "ledger_id_derivation".to_string(),
                        details: format!(
                            "ledger_id {} ≠ derived {} (op_pubkey, reserves_id, genesis_block)",
                            hex::encode(update.ledger_id),
                            hex::encode(derived),
                        ),
                    });
                }
            }
        }

        // 8. State machine + conformance.
        let op = LedgerOperation::tlv_decode(&update.message).map_err(|e| {
            crate::DepositsError::ProtocolViolation {
                violation_type: "message_decode".to_string(),
                details: format!("{:?}", e),
            }
        })?;
        let (mut next, violations) =
            self.apply_with_verifier(&op, authorizer, update.block_height)?;
        if let Some(v) = violations.first() {
            return Err(crate::DepositsError::ProtocolViolation {
                violation_type: "conformance".to_string(),
                details: v.to_string(),
            });
        }

        // The update has been fully blessed — bump sequence and transition
        // chain_tip_hash to `chain_hash()` (= SHA256(content_hash ||
        // operator_signature)), the value subsequent updates' `previous_hash`
        // must link against. Callers that used to do this by hand after
        // `apply_with_verifier` + finalize_chain_hash no longer need to.
        next.sequence = update.sequence_number;
        next.chain_tip_hash = update.chain_hash();
        Ok(next)
    }
    ///
    /// Returns the violations a cosigner would see, without mutating
    /// state. This is the gate every signer (operator before staging,
    /// cosigner before signing) runs against the operation before
    /// committing cryptographic weight to it. If the cosigner refuses
    /// to sign any operation that fails `check_speculative`, then by
    /// induction every `SignedLedgerUpdate` that ever advances state
    /// has already been blessed for conformance — which is what makes
    /// the `LedgerState::apply(SignedLedgerUpdate, ...)` path safe to
    /// apply unconditionally on the threshold-cosig invariant.
    ///
    /// Mechanically: apply the op speculatively, then run conformance
    /// against the post-apply state with `Some(pre_state)` so
    /// pre-state-dependent checks (e.g. `DepositKeyRotate` witness
    /// against the OLD descriptor) work. Either step's failure surfaces
    /// as a violation: state-machine errors (invalid transitions) get
    /// wrapped into a `ConformanceViolation::StateMachineRejected`.
    pub fn check_speculative(
        &self,
        operation: &crate::messages::LedgerOperation,
        authorizer: &impl crate::types::Authorizer,
        current_height: u32,
    ) -> Vec<ConformanceViolation> {
        match self.apply(operation) {
            Ok(next) => {
                next.check_conformance(operation, Some(self), authorizer, current_height)
            }
            Err(e) => vec![ConformanceViolation::StateMachineRejected {
                detail: format!("{:?}", e),
            }],
        }
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
        authorizer: &impl crate::types::Authorizer,
        current_height: u32,
    ) -> Vec<ConformanceViolation> {
        use crate::messages::LedgerOperation;

        let mut violations = Vec::new();

        // Reserve sufficiency: after any credit, total deposits must not exceed reserves.
        // Plus collateral ceiling: while a quorum is active, total deposits also
        // can't push past the declared collateral envelope.
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
                if self.quorum_state == crate::types::QuorumState::Active
                    && obligations > self.collateral_amount
                {
                    violations.push(ConformanceViolation::ExceedsCollateral {
                        credit: obligations,
                        collateral: self.collateral_amount,
                    });
                }
            }
            _ => {}
        }

        // Lock-class operations must not be zero-amount. The state
        // machine accepts `lock(0)` silently, so conformance is the
        // gate that catches semantically empty locks.
        match operation {
            LedgerOperation::InvoiceLock { amount, .. } if *amount == 0 => {
                violations.push(ConformanceViolation::ZeroAmount {
                    operation: "InvoiceLock",
                });
            }
            LedgerOperation::OnchainLock { amount, .. } if *amount == 0 => {
                violations.push(ConformanceViolation::ZeroAmount {
                    operation: "OnchainLock",
                });
            }
            LedgerOperation::TransferLock { amount, .. } if *amount == 0 => {
                violations.push(ConformanceViolation::ZeroAmount {
                    operation: "TransferLock",
                });
            }
            _ => {}
        }

        // OnchainLock: destination must be a non-empty string.
        if let LedgerOperation::OnchainLock {
            destination_address,
            ..
        } = operation
        {
            if destination_address.is_empty() {
                violations.push(ConformanceViolation::EmptyDestination);
            }
        }

        // Per-deposit replay protection. Each signature-bearing op carries
        // (nonce, expiry); the deposit tracks a set of (nonce, expiry) pairs
        // already accepted. An op is rejected if:
        //   (a) `op.expiry < current_height` — the signature's window has passed
        //       (ExpiryPassed)
        //   (b) `op.nonce` matches any not-yet-GC'd entry's nonce — replay within
        //       an unexpired window (NonceReplay)
        // GC happens lazily here: entries whose expiry is below current_height
        // can't be replayed anyway (ExpiryPassed would catch them) so they're
        // dropped before the uniqueness check. On accept, apply() inserts the new
        // (nonce, expiry) pair into the set. See PLAN-dep16-integration.md phase 5c.
        //
        // The check needs the deposit's pre-state because apply() has already
        // inserted into seen_nonces by the time conformance runs; comparing against
        // post-state would always self-match. Without pre_state we skip the check
        // (it's available on every apply_with_verifier* / apply_signed* path).
        if let Some(pre) = pre_state {
            let (op_name, deposit_id, op_nonce, op_expiry) = match operation {
                LedgerOperation::InvoiceLock { deposit_id, nonce, expiry, .. } => {
                    ("InvoiceLock", Some(deposit_id), Some(*nonce), Some(*expiry))
                }
                LedgerOperation::OnchainLock { deposit_id, nonce, expiry, .. } => {
                    ("OnchainLock", Some(deposit_id), Some(*nonce), Some(*expiry))
                }
                LedgerOperation::TransferLock { source_deposit_id, nonce, expiry, .. } => {
                    ("TransferLock", Some(source_deposit_id), Some(*nonce), Some(*expiry))
                }
                LedgerOperation::DepositKeyRotate { deposit_id, nonce, expiry, .. } => {
                    ("DepositKeyRotate", Some(deposit_id), Some(*nonce), Some(*expiry))
                }
                _ => ("", None, None, None),
            };
            if let (Some(deposit_id), Some(op_nonce), Some(op_expiry)) =
                (deposit_id, op_nonce, op_expiry)
            {
                // (a) Expiry check: the signature has already fallen out of its
                // validity window.
                if op_expiry < current_height {
                    violations.push(ConformanceViolation::ExpiryPassed {
                        operation: op_name,
                        expiry: op_expiry,
                        current_height,
                    });
                }
                // (b) Replay check, with lazy GC.
                if let Some(prev_deposit) = pre.deposits.get(deposit_id) {
                    let nonce_replayed = prev_deposit
                        .seen_nonces
                        .iter()
                        .any(|(seen_nonce, seen_expiry)| {
                            *seen_expiry >= current_height && *seen_nonce == op_nonce
                        });
                    if nonce_replayed {
                        violations.push(ConformanceViolation::NonceReplay {
                            operation: op_name,
                            actual: op_nonce,
                        });
                    }
                }
            }
        }

        // DepositKeyRotate: the new descriptor must parse — otherwise
        // the post-rotation deposit becomes unspendable through the
        // normal authorization path.
        if let LedgerOperation::DepositKeyRotate { new_descriptor, .. } = operation {
            if let Some(detail) = authorizer.validate_descriptor(new_descriptor) {
                violations.push(ConformanceViolation::UnparseableDescriptor {
                    operation: "DepositKeyRotate",
                    detail,
                });
            }
        }

        // DepositOpen: the descriptor must parse and (if a quorum is
        // active) fit within the smallest member-declared size cap.
        if let LedgerOperation::DepositOpen { descriptor, .. } = operation {
            if let Some(detail) = authorizer.validate_descriptor(descriptor) {
                violations.push(ConformanceViolation::UnparseableDescriptor {
                    operation: "DepositOpen",
                    detail,
                });
            }
            if let Some(max) = self
                .quorum_members
                .iter()
                .filter_map(|m| m.max_descriptor_bytes)
                .min()
            {
                if descriptor.len() as u32 > max {
                    violations.push(ConformanceViolation::DescriptorTooLarge {
                        actual: descriptor.len(),
                        max,
                    });
                }
            }
        }

        // FeeCollect: refuse if the operator is firing before the
        // depositor's `frequency_blocks` cadence has elapsed. The
        // op carries its own observed block_height, so no extra
        // signature plumbing is needed.
        if let LedgerOperation::FeeCollect {
            deposit_id,
            block_height,
            ..
        } = operation
        {
            if let Some(pre) = pre_state {
                if let Some(deposit) = pre.deposits.get(deposit_id) {
                    let next_allowed = deposit
                        .last_fee_assessment
                        .saturating_add(deposit.fees.frequency_blocks);
                    if *block_height < next_allowed {
                        violations.push(ConformanceViolation::FeeWindowNotElapsed {
                            current_block: *block_height,
                            next_allowed_block: next_allowed,
                        });
                    }
                }
            }
        }

        // Witness verification for operations that carry authorization proofs. Phase 5:
        // all three lock-side variants route through the dep-16 Authorizer. The signing
        // message is the dep-17 operation preimage (built from op_type + args + nonce +
        // expiry + deposit_id), not a per-op signing-helper digest — replay protection
        // binds to the full op shape.
        match operation {
            LedgerOperation::InvoiceLock { deposit_id, .. } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    if !authorizer.authorize(&deposit.descriptor, operation) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "InvoiceLock",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
            }
            LedgerOperation::InvoiceFulfill {
                payment_id,
                preimage,
                ..
            } => {
                // Phase 5: descriptor evaluation dropped (the lock was already
                // authorized at InvoiceLock time; re-evaluating at fulfill time would be
                // unsound — see PLAN-dep16-integration.md's "two carve-outs"). Only the
                // preimage→payment_id binding stays: the preimage IS the release
                // condition, and it must match the hash the original lock committed to.
                let hash = sha256::Hash::hash(preimage).to_byte_array();
                if hash != *payment_id {
                    violations.push(ConformanceViolation::InvalidWitness {
                        operation: "InvoiceFulfill",
                        detail: "preimage does not match payment hash".to_string(),
                    });
                }
            }
            LedgerOperation::OnchainLock { deposit_id, .. } => {
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    if !authorizer.authorize(&deposit.descriptor, operation) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "OnchainLock",
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
            }
            LedgerOperation::TransferLock { source_deposit_id, .. } => {
                // Look up descriptor from the state BEFORE this operation was applied.
                // Since apply() already consumed the balance, we check against current state
                // where the deposit still exists.
                if let Some(deposit) = self.deposits.get(source_deposit_id) {
                    if !authorizer.authorize(&deposit.descriptor, operation) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: "TransferLock",
                            detail: "witness does not satisfy source deposit descriptor"
                                .to_string(),
                        });
                    }
                }
            }
            LedgerOperation::TransferComplete { transfer_id, .. } => {
                // Phase 5: TransferComplete's script_witness is authorized against the
                // lock's completion_script — the release descriptor specified at
                // TransferLock time. apply() has already removed the pending_transfer
                // entry from `next.pending_transfers` and unwound the lock; we look up
                // the entry in pre_state to find the completion_script.
                //
                // Without this check, the script_witness on TransferComplete was data
                // the protocol carried but never enforced — any caller could trigger
                // a transfer completion regardless of what the lock's release script
                // required.
                if let Some(pre) = pre_state {
                    if let Some(pending) = pre.pending_transfers.get(transfer_id) {
                        if !authorizer.authorize(&pending.completion_script, operation) {
                            violations.push(ConformanceViolation::InvalidWitness {
                                operation: "TransferComplete",
                                detail: "script_witness does not satisfy lock's completion_script"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
            LedgerOperation::DepositKeyRotate {
                deposit_id, ..
            } => {
                // The witness must satisfy the OLD descriptor (proving authorization to
                // rotate). apply() already updated the descriptor, so we use pre_state to get
                // the old one.
                //
                // Phase 4: routed through the dep-16 Authorizer. The signing message is the
                // dep-17 operation preimage sighash (built from nonce/expiry/op_type/args/
                // deposit_id), not SHA256(new_descriptor) — replay protection now binds to
                // the full op shape, not just the candidate descriptor bytes.
                if let Some(pre) = pre_state {
                    if let Some(old_deposit) = pre.deposits.get(deposit_id) {
                        if !authorizer.authorize(&old_deposit.descriptor, operation) {
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

#[cfg(test)]
mod replay_protection_tests {
    //! Replay protection (phase 5c): the per-deposit `seen_nonces` set captures every
    //! (nonce, expiry) pair the deposit has accepted within an unexpired window.
    //!   * `NonceReplay` fires when a new op's nonce matches a not-yet-GC'd entry.
    //!   * `ExpiryPassed` fires when a new op's expiry is already below current_height.
    //!   * Entries with `expiry < current_height` are GC'd lazily on each check —
    //!     the corresponding signature can't be applied anyway (ExpiryPassed catches
    //!     it), so the nonce becomes safe to reuse.
    //! See PLAN-dep16-integration.md phase 5c.

    use super::*;
    use crate::messages::LedgerOperation;
    use crate::types::{Authorizer, DescriptorWitness};
    use crate::Deposit;

    /// A no-op authorizer used so the nonce/expiry tests aren't entangled with
    /// descriptor authorization — those have their own coverage. (AllowAll is in
    /// `crate::types::AllowAll` but we re-declare for clarity here.)
    struct AllowAuthorizer;
    impl Authorizer for AllowAuthorizer {
        fn authorize(&self, _: &str, _: &LedgerOperation) -> bool {
            true
        }
    }

    fn state_with_one_deposit() -> (LedgerState, [u8; 16]) {
        let operator_key = bitcoin::secp256k1::PublicKey::from_slice(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap();
        let mut state = LedgerState::new(operator_key, "test_reserves".to_string(), 0);
        let descriptor = "pk(02000000000000000000000000000000000000000000000000000000000000\
                          000000)"
            .to_string();
        let mut deposit = Deposit::new(descriptor, None);
        deposit.balance = 1000;
        let did = deposit.deposit_id;
        state.deposits.insert(did, deposit);
        (state, did)
    }

    fn invoice_lock(
        did: [u8; 16],
        amount: u64,
        payment_id: [u8; 32],
        nonce: u64,
        expiry: u32,
    ) -> LedgerOperation {
        LedgerOperation::InvoiceLock {
            deposit_id: did,
            amount,
            payment_id,
            sequence_number: nonce,
            nonce,
            expiry,
            witness: DescriptorWitness::new(),
        }
    }

    fn apply(
        state: &LedgerState,
        op: &LedgerOperation,
        current_height: u32,
    ) -> (LedgerState, Vec<ConformanceViolation>) {
        state
            .apply_with_verifier(op, &AllowAuthorizer, current_height)
            .expect("apply")
    }

    /// A first op against a fresh deposit (seen_nonces empty) is accepted; the
    /// (nonce, expiry) pair lands in seen_nonces for future replay checks.
    #[test]
    fn first_op_is_accepted_and_recorded() {
        let (state, did) = state_with_one_deposit();
        let op = invoice_lock(did, 50, [0xab; 32], 42, 1000);
        let (next, violations) = apply(&state, &op, 500);
        assert!(
            !violations
                .iter()
                .any(|v| matches!(v, ConformanceViolation::NonceReplay { .. }
                    | ConformanceViolation::ExpiryPassed { .. })),
            "first op must not raise replay/expiry: {:?}",
            violations,
        );
        assert!(next.deposits[&did].seen_nonces.contains(&(42, 1000)));
    }

    /// A second op with the same nonce as the first (and both within their windows)
    /// is rejected as a replay.
    #[test]
    fn replayed_nonce_is_flagged() {
        let (state, did) = state_with_one_deposit();
        let op1 = invoice_lock(did, 50, [0xab; 32], 42, 1000);
        let (state, _) = apply(&state, &op1, 500);
        let op2 = invoice_lock(did, 50, [0xcd; 32], 42, 1000); // same nonce
        let (_, violations) = apply(&state, &op2, 500);
        assert!(
            violations.iter().any(|v| matches!(
                v,
                ConformanceViolation::NonceReplay { actual: 42, .. }
            )),
            "replayed nonce must raise NonceReplay: got {:?}",
            violations,
        );
    }

    /// An op whose expiry is already below current_height is rejected as expired,
    /// even if the nonce is fresh.
    #[test]
    fn expired_op_is_flagged() {
        let (state, did) = state_with_one_deposit();
        // current_height = 2000, op.expiry = 1000 → already passed
        let op = invoice_lock(did, 50, [0xab; 32], 99, 1000);
        let (_, violations) = apply(&state, &op, 2000);
        assert!(
            violations.iter().any(|v| matches!(
                v,
                ConformanceViolation::ExpiryPassed {
                    expiry: 1000,
                    current_height: 2000,
                    ..
                }
            )),
            "expired op must raise ExpiryPassed: got {:?}",
            violations,
        );
    }

    /// Once current_height passes the original op's expiry, the nonce can be reused.
    /// The GC drops the (nonce, old-expiry) entry before the uniqueness check.
    #[test]
    fn nonce_becomes_reusable_after_window_passes() {
        let (state, did) = state_with_one_deposit();
        // Apply op1 with expiry=1000 at height 500.
        let op1 = invoice_lock(did, 50, [0xab; 32], 42, 1000);
        let (state, _) = apply(&state, &op1, 500);
        // Time passes — current_height advances past op1's expiry. Reuse nonce=42.
        let op2 = invoice_lock(did, 50, [0xcd; 32], 42, 5000);
        let (_, violations) = apply(&state, &op2, 2000);
        assert!(
            !violations
                .iter()
                .any(|v| matches!(v, ConformanceViolation::NonceReplay { .. })),
            "nonce reuse after expiry must not be a replay: got {:?}",
            violations,
        );
    }

    /// Random (non-monotonic) nonces are accepted across a sequence — what the
    /// wallet actually picks. The protocol does not require monotonic ordering.
    #[test]
    fn random_nonces_chain_cleanly_within_window() {
        let (mut state, did) = state_with_one_deposit();
        for (idx, nonce) in [12345u64, 999, 1_000_000, 7].iter().enumerate() {
            let op = invoice_lock(did, 10, [idx as u8; 32], *nonce, 10_000);
            let (next, violations) = apply(&state, &op, 500);
            assert!(
                !violations
                    .iter()
                    .any(|v| matches!(v, ConformanceViolation::NonceReplay { .. })),
                "non-monotonic op {} (nonce={}) raised NonceReplay: {:?}",
                idx, nonce, violations,
            );
            assert!(next.deposits[&did].seen_nonces.contains(&(*nonce, 10_000)));
            state = next;
        }
    }

    /// Fulfill variants don't carry a `nonce` field — they shouldn't trigger
    /// the replay check at all.
    #[test]
    fn invoice_fulfill_is_not_subject_to_replay_check() {
        let (state, did) = state_with_one_deposit();
        let (state, _) = apply(&state, &invoice_lock(did, 50, [0xab; 32], 1, 1000), 500);
        let fulfill = LedgerOperation::InvoiceFulfill {
            deposit_id: did,
            amount: 50,
            payment_id: [0xab; 32],
            sequence_number: 2,
            preimage: [0xee; 32],
            witness: DescriptorWitness::new(),
        };
        let (_, violations) = apply(&state, &fulfill, 500);
        assert!(
            !violations.iter().any(|v| matches!(
                v,
                ConformanceViolation::NonceReplay { .. }
                    | ConformanceViolation::ExpiryPassed { .. }
            )),
            "fulfill ops must not run the replay/expiry checks: {:?}",
            violations,
        );
    }
}
