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

/// Serde default for `LedgerState::active_ruleset_name`: no ruleset until a
/// `QuorumBegin` commits one.
fn default_ruleset_name() -> String {
    String::new()
}

/// Whether a ledger's active ruleset enforces the DEP-07 one-period maintenance
/// fee cap as a consensus rule (`FeeExceedsAssessment`). Version-gated per
/// DEP-18: dormant until a ledger is upgraded (`QuorumUpgrade`/`QuorumBegin`) to
/// `fee-cap-v3`, so an upgraded node never retroactively faults a pre-upgrade
/// `FeeCollect` and trips the DEP-06 confiscation cascade. Keyed by ruleset name
/// (the reserves half of `fee-cap-v3` lives in `deposits-core::ruleset`).
pub fn ruleset_enforces_fee_cap(ruleset_name: &str) -> bool {
    // `balance-commit-v4` is a strict superset of `fee-cap-v3` (its rules plus
    // the balance-commitment requirement), so it enforces the fee cap too.
    matches!(ruleset_name, "fee-cap-v3" | "balance-commit-v4")
}

/// Whether a ledger's active ruleset REQUIRES a balance commitment on every
/// balance-touching op (DEP-02 §Balance Commitments, `MissingBalanceCommitment`).
/// Version-gated per DEP-18: dormant until a ledger is upgraded to
/// `balance-commit-v4`, so commitment-less ops on legacy / `fee-cap-v3` ledgers
/// stay conforming. The *verify-when-present* rule (a declared commitment must
/// match the replayed state) is intrinsic to every ruleset and is NOT gated by
/// this — see `check_conformance`.
pub fn ruleset_requires_balance_commitments(ruleset_name: &str) -> bool {
    matches!(ruleset_name, "balance-commit-v4")
}

/// Whether this binary knows the named ruleset at all. Mirrors the
/// `deposits-core::ruleset` registry's `lookup`, kept here because conformance
/// (which can't depend on deposits-core) needs to reject a `QuorumUpgrade` to an
/// unknown target. Keep the two in sync when adding a ruleset.
pub fn ruleset_known(ruleset_name: &str) -> bool {
    !reserves_family(ruleset_name).is_empty()
}

/// The on-chain reserves-cascade family a ruleset belongs to (DEP-18). Two
/// rulesets in the same family produce byte-identical reserves UTXO scripts and
/// differ only in off-chain op rules, so a ledger may move between them with a
/// cheap `QuorumUpgrade` (no reserves move). Returns "" for unknown names.
/// Mirrors `deposits-core::ruleset`'s reserves factories: `fee-cap-v3` reuses
/// the `cltv-offset-v2` cascade.
pub fn reserves_family(ruleset_name: &str) -> &'static str {
    match ruleset_name {
        "cltv-offset-v2" | "fee-cap-v3" | "balance-commit-v4" => "cltv-offset-v2",
        _ => "",
    }
}

// ============================================================================
// DEP-20 §3 exits
// ============================================================================

/// A pending ExitRequest, keyed in `pending_exits` by its update's `chain_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExit {
    pub deposit_id: DepositId,
    pub amount: u64,
    pub exit_address: Vec<u8>,
    pub expires_at: Option<u32>,
    pub block_height: u32,
    pub seq: u64,
}

/// DEP-11 default `exit_cutoff_margin_blocks`.
pub const EXIT_CUTOFF_MARGIN_BLOCKS: u32 = 144;
/// DEP-20 §3: requests below 330 sats are carried, not settled.
pub const EXIT_DUST_MSATS: u64 = 330_000;

/// The update envelope an operation is applied under (block height, sequence, chain_hash):
/// ExitRequest ids, expiry and the exit due set need it, and `apply_in_place` sees only the op.
#[derive(Clone, Copy, Debug, Default)]
pub struct ApplyCtx {
    pub height: u32,
    pub seq: u64,
    pub hash: [u8; 32],
}

thread_local! {
    static APPLY_CTX: std::cell::Cell<ApplyCtx> = std::cell::Cell::new(ApplyCtx::default());
}

/// Run `f` with `ctx` as the apply context (restored afterwards).
pub fn with_apply_ctx<R>(ctx: ApplyCtx, f: impl FnOnce() -> R) -> R {
    let prev = APPLY_CTX.with(|c| c.replace(ctx));
    let r = f();
    APPLY_CTX.with(|c| c.set(prev));
    r
}

fn apply_ctx() -> ApplyCtx {
    APPLY_CTX.with(|c| c.get())
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
    /// Block height at which the active quorum's `QuorumBegin` was
    /// committed. With `quorum_expiry` this gives the full quorum
    /// *duration* (expiry − begin). Stamped from the update envelope on
    /// commit/replay (the block height isn't carried in the op itself),
    /// so it's `None` until a QuorumBegin lands or on legacy states
    /// reconstructed without block context.
    #[serde(default)]
    pub quorum_begin_block: Option<u32>,
    /// Sequence number of that `QuorumBegin` update — the entry that
    /// established the active quorum. Lets clients jump straight to it.
    #[serde(default)]
    pub quorum_begin_sequence: Option<u64>,
    /// Content hash of that `QuorumBegin` update (the entry's id on the
    /// hash chain), for linking back to it in explorers.
    #[serde(default)]
    pub quorum_begin_hash: Option<[u8; 32]>,
    /// Protocol-ruleset name this ledger is currently governed by.
    /// Set from `QuorumBegin.protocol_version` (required); empty before the
    /// first `QuorumBegin`.
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
    /// Cached sum of every deposit's `balance` — the operator's total obligation.
    /// Maintained incrementally by `apply_in_place` (the sole production site
    /// that mutates deposit balances) so the reserve-sufficiency conformance
    /// check is O(1) instead of an O(#deposits) fold per credit/withdraw/transfer
    /// op. `total_deposit_balance()` returns this; `fold_deposit_balance()` is
    /// the O(#deposits) ground truth used by the debug-build drift assertion and
    /// `rebuild_balance_cache()`. `#[serde(default)]`: pre-cache ledgers load
    /// with 0, then every production load path (startup replay, from_export,
    /// recompute_state) rebuilds state through `apply_in_place` from genesis,
    /// which repopulates it correctly.
    #[serde(default)]
    pub total_deposit_balance: u64,
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
    /// DEP-20 §3 pending exit requests (id = the ExitRequest update's chain_hash).
    #[serde(with = "serde_transfer_id_map", default)]
    pub pending_exits: HashMap<[u8; 32], PendingExit>,
    /// A QuorumBegin vault the next QuorumBegin rotates (cleared by DisputeAcquire).
    #[serde(default)]
    pub vault_current: bool,
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
            quorum_begin_block: None,
            quorum_begin_sequence: None,
            quorum_begin_hash: None,
            active_ruleset_name: default_ruleset_name(),
            collateral_amount: 0,
            pending_transfers: HashMap::new(),
            open_invoice_locks: HashMap::new(),
            pending_withdrawals: HashMap::new(),
            credited_payments: im::OrdSet::new(),
            total_deposit_balance: 0,
            fees_accumulated: 0,
            sequence: 0,
            chain_tip_hash: [0u8; 32],
            joined_quorums: Vec::new(),
            dispute_state: DisputeState::Normal,
            parent_pubkey: operator_key,
            quorum_at_fork: Vec::new(),
            dispute_fork_sequence: 0,
            pending_exits: HashMap::new(),
            vault_current: false,
        }
    }

    /// DEP-20 §3 due set at `height` under `cutoff`: pending requests appended at block
    /// height <= cutoff, at least the dust floor, unexpired, in append order.
    pub fn due_exits(&self, height: u32, cutoff: u32) -> Vec<([u8; 32], PendingExit)> {
        let mut due: Vec<([u8; 32], PendingExit)> = self
            .pending_exits
            .iter()
            .filter(|(_, e)| {
                e.block_height <= cutoff
                    && e.amount >= EXIT_DUST_MSATS
                    && e.expires_at.is_none_or(|x| x > height)
            })
            .map(|(k, e)| (*k, e.clone()))
            .collect();
        due.sort_by_key(|(_, e)| e.seq);
        due
    }

    fn has_expired_exits(&self, height: u32) -> bool {
        self.pending_exits
            .values()
            .any(|e| e.expires_at.is_some_and(|x| x <= height))
    }

    /// DEP-20 §3 expiry: release every pending request with expires_at_height <= height.
    fn release_expired_exits(&mut self, height: u32) {
        let gone: Vec<[u8; 32]> = self
            .pending_exits
            .iter()
            .filter(|(_, e)| e.expires_at.is_some_and(|x| x <= height))
            .map(|(k, _)| *k)
            .collect();
        for k in gone {
            if let Some(e) = self.pending_exits.remove(&k) {
                if let Some(d) = self.deposits.get_mut(&e.deposit_id) {
                    d.unlock(e.amount);
                }
            }
        }
    }

    /// Record where the active quorum's `QuorumBegin` was committed. The
    /// block height / sequence / content hash live on the update
    /// envelope rather than the op, so the append + replay paths call
    /// this right after applying a QuorumBegin — mirrors how
    /// `opened_at_block` is stamped for DepositOpen.
    pub fn note_quorum_begin(&mut self, block_height: u32, sequence: u64, content_hash: [u8; 32]) {
        self.quorum_begin_block = Some(block_height);
        self.quorum_begin_sequence = Some(sequence);
        self.quorum_begin_hash = Some(content_hash);
    }

    /// One replay step: decode `update`'s operation, apply it in place, then
    /// run the post-hooks that need the update envelope (a DepositOpen's
    /// `opened_at_block`, a QuorumBegin's `note_quorum_begin`) and advance
    /// `sequence` / `chain_tip_hash`. Returns the decoded operation.
    ///
    /// Every replay from genesis goes through this (`Ledger::recompute_state`,
    /// the dispute fork's `fork_state_at`, the `NonConformingUpdate` verifier),
    /// so a state rebuilt for a proof is the state the ledger itself holds.
    /// On error nothing has been mutated.
    pub fn apply_update_in_place(
        &mut self,
        update: &crate::types::SignedLedgerUpdate,
    ) -> crate::DepositsResult<crate::messages::LedgerOperation> {
        use crate::messages::LedgerOperation;
        use crate::tlv::TlvDecode;

        let op = LedgerOperation::tlv_decode(&update.message).map_err(|e| {
            crate::DepositsError::ProtocolViolation {
                violation_type: "replay_decode".to_string(),
                details: format!("seq {}: {}", update.sequence_number, e),
            }
        })?;
        let ctx = ApplyCtx {
            height: update.block_height,
            seq: update.sequence_number,
            hash: update.chain_hash(),
        };
        with_apply_ctx(ctx, || self.apply_in_place(&op))?;
        if let LedgerOperation::DepositOpen { deposit_id, .. } = &op {
            if update.block_height > 0 {
                if let Some(deposit) = self.deposits.get_mut(deposit_id) {
                    deposit.opened_at_block = update.block_height;
                    if deposit.last_fee_assessment == 0 {
                        deposit.last_fee_assessment = update.block_height;
                    }
                }
            }
        }
        if matches!(op, LedgerOperation::QuorumBegin { .. }) {
            self.note_quorum_begin(
                update.block_height,
                update.sequence_number,
                update.content_hash,
            );
        }
        self.sequence = update.sequence_number;
        self.chain_tip_hash = update.chain_hash();
        Ok(op)
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
    /// [`apply`](Self::apply) under `update`'s envelope (block height, sequence, chain_hash):
    /// what a replay loop over raw updates needs (DEP-20 exits read all three).
    pub fn apply_for(
        &self,
        update: &crate::types::SignedLedgerUpdate,
        operation: &crate::messages::LedgerOperation,
    ) -> crate::DepositsResult<Self> {
        let ctx = ApplyCtx {
            height: update.block_height,
            seq: update.sequence_number,
            hash: update.chain_hash(),
        };
        with_apply_ctx(ctx, || self.apply(operation))
    }

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
        // DEP-20 §3: before an update's operation, release the exit requests that expired at
        // or below its height (on a scratch copy, so a failing op leaves state untouched).
        let h = apply_ctx().height;
        if h > 0 && self.has_expired_exits(h) {
            let mut scratch = self.clone();
            scratch.release_expired_exits(h);
            scratch.apply_op_in_place(operation)?;
            *self = scratch;
            return Ok(());
        }
        self.apply_op_in_place(operation)
    }

    fn apply_op_in_place(
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
                exit_cutoff_height,
                exit_outputs,
                ..
            } => {
                // DEP-20 §3: exit_outputs must be exactly the due set (rotating QuorumBegins).
                let settled: Vec<[u8; 32]> = if next.vault_current {
                    let h = apply_ctx().height;
                    let cutoff =
                        exit_cutoff_height.unwrap_or(h.saturating_sub(EXIT_CUTOFF_MARGIN_BLOCKS));
                    if cutoff > h || cutoff < h.saturating_sub(EXIT_CUTOFF_MARGIN_BLOCKS) {
                        return Err(crate::DepositsError::ProtocolViolation {
                            violation_type: "exit_cutoff".to_string(),
                            details: format!(
                                "cutoff {} outside [{}, {}]",
                                cutoff,
                                h.saturating_sub(EXIT_CUTOFF_MARGIN_BLOCKS),
                                h
                            ),
                        });
                    }
                    let due = next.due_exits(h, cutoff);
                    let matches = due.len() == exit_outputs.len()
                        && due.iter().zip(exit_outputs.iter()).enumerate().all(
                            |(i, ((_, e), o))| {
                                o.deposit_id == e.deposit_id
                                    && o.amount == e.amount
                                    && o.vout as usize == i + 1
                            },
                        );
                    if !matches {
                        return Err(crate::DepositsError::ProtocolViolation {
                            violation_type: "exit_outputs".to_string(),
                            details: format!(
                                "{} due exits, {} settled or mismatched",
                                due.len(),
                                exit_outputs.len()
                            ),
                        });
                    }
                    due.into_iter().map(|(k, _)| k).collect()
                } else {
                    if !exit_outputs.is_empty() {
                        return Err(crate::DepositsError::ProtocolViolation {
                            violation_type: "exit_outputs".to_string(),
                            details: "a QuorumBegin with no current vault settles no exits"
                                .to_string(),
                        });
                    }
                    Vec::new()
                };
                let chosen_ruleset = protocol_version.clone().unwrap_or_default();
                if !ruleset_known(&chosen_ruleset) {
                    return Err(crate::DepositsError::ProtocolViolation {
                        violation_type: "unknown_ruleset".to_string(),
                        details: format!(
                            "QuorumBegin protocol_version {:?} is not a known ruleset",
                            protocol_version
                        ),
                    });
                }

                // Promote the subset of staged members that the operation
                // declared (validated upstream to be ⊆ next_quorum_members).
                // Members in next_quorum_members that the operation
                // *omitted* are dropped — they never enter the active set.
                //
                // Compute `promoted` by cloning rather than draining
                // next_quorum_members: the ruleset gate below can `return Err`,
                // and apply_in_place must leave state untouched on failure (the
                // documented atomicity invariant). next_quorum_members is only
                // cleared once every check has passed. The clone is bounded by
                // quorum size (handful of members), not by ledger size.
                let declared: std::collections::HashSet<_> =
                    quorum_members.iter().map(|m| m.pubkey).collect();
                let promoted: Vec<QuorumMember> = next
                    .next_quorum_members
                    .iter()
                    .filter(|m| declared.contains(&m.pubkey))
                    .cloned()
                    .collect();

                // Ruleset attestation gate: every promoted member must have
                // signed a `QuorumMemberResponse` declaring support, otherwise
                // we have no proof this member can validate the rules we're
                // about to commit to. Caught here in `apply` so every node that
                // replays the chain enforces it, not just the rotating operator.
                {
                    let unsupported: Vec<String> = promoted
                        .iter()
                        .filter(|m| !m.supported_rulesets.iter().any(|s| s == &chosen_ruleset))
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

                // All checks passed — commit. Clearing next_quorum_members here
                // (instead of draining it above) is what makes the failure path
                // leave state untouched.
                next.next_quorum_members.clear();
                next.reserves_key = reserves_id.clone();
                next.reserves_amount = *amount;
                next.collateral_amount = *collateral_amount;
                next.quorum_expiry = Some(*quorum_expiry);
                next.active_ruleset_name = chosen_ruleset;
                next.quorum_members = promoted;
                next.quorum_state = QuorumState::Active;
                for k in settled {
                    if let Some(e) = next.pending_exits.remove(&k) {
                        if let Some(d) = next.deposits.get_mut(&e.deposit_id) {
                            let before = d.balance;
                            d.fulfill(e.amount);
                            let after = d.balance;
                            next.add_balance_delta(before, after);
                        }
                    }
                }
                next.vault_current = true;
            }
            LedgerOperation::ExitRequest {
                deposit_id,
                amount,
                exit_address,
                expires_at_height,
                nonce,
                expiry,
                ..
            } => {
                if *amount == 0 {
                    return Err(crate::DepositsError::ProtocolViolation {
                        violation_type: "exit_amount".to_string(),
                        details: "zero".to_string(),
                    });
                }
                let ctx = apply_ctx();
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.lock(*amount)?;
                deposit.seen_nonces.insert((*nonce, *expiry));
                // DEP-20 §3: the request id is SHA256 of the operation's TLV bytes.
                let id = {
                    use crate::tlv::TlvEncode;
                    sha256::Hash::hash(&operation.tlv_encode()).to_byte_array()
                };
                next.pending_exits.insert(
                    id,
                    PendingExit {
                        deposit_id: *deposit_id,
                        amount: *amount,
                        exit_address: exit_address.clone(),
                        expires_at: *expires_at_height,
                        block_height: ctx.height,
                        seq: ctx.seq,
                    },
                );
            }
            LedgerOperation::ExitCancel {
                deposit_id,
                exit_request_id,
                nonce,
                expiry,
                ..
            } => {
                let pending = next
                    .pending_exits
                    .get(exit_request_id)
                    .filter(|e| &e.deposit_id == deposit_id)
                    .cloned()
                    .ok_or_else(|| crate::DepositsError::ProtocolViolation {
                        violation_type: "exit_cancel".to_string(),
                        details: "names no pending exit request of this deposit".to_string(),
                    })?;
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.unlock(pending.amount);
                deposit.seen_nonces.insert((*nonce, *expiry));
                next.pending_exits.remove(exit_request_id);
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
                let opened_balance = deposit.balance;
                next.deposits.insert(*deposit_id, deposit);
                // Deposits open at zero balance today; fold in whatever they
                // carry so the cache stays correct if that ever changes.
                next.add_balance_delta(0, opened_balance);
            }
            LedgerOperation::DepositClose { deposit_id, .. } => {
                let deposit = next
                    .deposits
                    .get(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                if deposit.balance > 0 {
                    return Err(crate::DepositsError::NonZeroBalance {
                        balance: deposit.balance,
                    });
                }
                let closed_balance = deposit.balance;
                next.deposits.remove(deposit_id);
                next.add_balance_delta(closed_balance, 0);
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
                let before = deposit.balance;
                deposit.credit(*amount);
                let after = deposit.balance;
                next.credited_payments.insert(hash_hex);
                next.add_balance_delta(before, after);
            }
            LedgerOperation::InvoiceLock {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                nonce,
                expiry,
                timeout_height,
                fee,
                witness,
                ..
            } => {
                // Operator fee budget locked on top of the invoice amount
                // (keep-the-spread). None = legacy amount-only lock.
                let fee_msats = fee.unwrap_or(0);
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.lock(*amount + fee_msats)?;
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
                        timeout_height: *timeout_height,
                        fee: fee_msats,
                    },
                );
            }
            LedgerOperation::InvoiceFail {
                payment_id,
                deposit_id,
                ..
            } => {
                // Release the full locked budget (amount + fee), read from the
                // open lock — the locked amount is authoritative state, not a
                // settable field on the op (matching TransferFail/OnchainFail,
                // which carry no amount). The op's own `amount` field is ignored
                // and slated for removal. The payment never went out, so the
                // operator keeps no spread — only the fixed dust fee below.
                let (locked_amount, fee_msats) = next
                    .open_invoice_locks
                    .get(payment_id)
                    .map(|l| (l.amount, l.fee))
                    .unwrap_or((0, 0));
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                deposit.unlock(locked_amount + fee_msats);
                // Even on failure, the fixed portion of the transfer fee
                // applies (the variable portion is zero since no amount
                // moved). Charged best-effort from current balance —
                // saturating_sub guards the edge where balance dipped
                // below the fixed fee between lock and fail.
                let before = deposit.balance;
                let charged = deposit.transfer_fees.fixed_msats.min(deposit.balance);
                deposit.balance -= charged;
                let after = deposit.balance;
                next.fees_accumulated = next.fees_accumulated.saturating_add(charged);
                next.open_invoice_locks.remove(payment_id);
                next.add_balance_delta(before, after);
            }
            LedgerOperation::InvoiceFulfill {
                payment_id,
                deposit_id,
                amount,
                ..
            } => {
                // Keep-the-spread: consume amount+fee from the deposit; the
                // `amount` funded the LN payment (left the system), and the
                // `fee` becomes operator revenue (the operator paid the actual
                // routing off-ledger and retains fee − actual_routing).
                let fee_msats = next
                    .open_invoice_locks
                    .get(payment_id)
                    .map(|l| l.fee)
                    .unwrap_or(0);
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                let before = deposit.balance;
                deposit.fulfill(*amount + fee_msats);
                let after = deposit.balance;
                next.open_invoice_locks.remove(payment_id);
                next.fees_accumulated = next.fees_accumulated.saturating_add(fee_msats);
                next.add_balance_delta(before, after);
            }
            LedgerOperation::OnchainCredit {
                deposit_id, amount, ..
            } => {
                let deposit = next
                    .deposits
                    .get_mut(deposit_id)
                    .ok_or(crate::DepositsError::DepositNotFound)?;
                let before = deposit.balance;
                deposit.credit(*amount);
                let after = deposit.balance;
                next.add_balance_delta(before, after);
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
                ..
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
                        let before = deposit.balance;
                        let charged = deposit.transfer_fees.fixed_msats.min(deposit.balance);
                        deposit.balance -= charged;
                        let after = deposit.balance;
                        next.fees_accumulated = next.fees_accumulated.saturating_add(charged);
                        next.add_balance_delta(before, after);
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
                        let before = deposit.balance;
                        deposit.fulfill(total);
                        let after = deposit.balance;
                        next.add_balance_delta(before, after);
                    }
                }
            }
            LedgerOperation::FeeCollect {
                deposit_id,
                amount,
                block_height,
                ..
            } => {
                if let Some(deposit) = next.deposits.get_mut(deposit_id) {
                    if let Some((new_fees, effective)) = deposit.pending_fee_change.take() {
                        if *block_height >= effective {
                            deposit.fees = new_fees;
                        } else {
                            deposit.pending_fee_change = Some((new_fees, effective));
                        }
                    }
                    let before = deposit.balance;
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                    deposit.last_fee_assessment = *block_height;
                    let after = deposit.balance;
                    next.fees_accumulated = next.fees_accumulated.saturating_add(*amount);
                    next.add_balance_delta(before, after);
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
                min_collateral_bps,
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
                    // QuorumAddMember without a blob: no declared support,
                    // so no QuorumBegin can promote this member.
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
                    min_collateral_bps: *min_collateral_bps,
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
            LedgerOperation::QuorumUpgrade {
                new_protocol_version,
            } => {
                // DEP-18 off-chain version bump: adopt the target op-rules
                // ruleset. Conformance (below) has already enforced that it is
                // a known ruleset in the same reserves-cascade family, so the
                // on-chain reserves UTXO is unaffected.
                next.active_ruleset_name = new_protocol_version.clone();
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
                next.vault_current = false;
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
                        let before = source.balance;
                        source.balance = source.balance.saturating_sub(pending.amount);
                        let after = source.balance;
                        next.add_balance_delta(before, after);
                    }
                    if let Some(dest) = next.deposits.get_mut(&pending.destination_deposit_id) {
                        let before = dest.balance;
                        dest.balance = dest.balance.saturating_add(pending.amount);
                        let after = dest.balance;
                        next.add_balance_delta(before, after);
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
                        let before = source.balance;
                        charged = source.transfer_fees.fixed_msats.min(source.balance);
                        source.balance -= charged;
                        let after = source.balance;
                        next.add_balance_delta(before, after);
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
        // Drift guard: the cached total must always equal the fold. Debug-only,
        // so it costs nothing in release but turns every apply in the whole test
        // suite into a check that the incremental maintenance above stays exact.
        debug_assert_eq!(
            next.total_deposit_balance,
            next.fold_deposit_balance(),
            "total_deposit_balance cache drifted from the deposit fold after {:?}",
            std::mem::discriminant(operation)
        );
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
        let violations = next.check_conformance(operation, Some(self), authorizer, current_height);
        Ok((next, violations))
    }

    /// Populate DEP-02 §Balance Commitments on `op` for the OPERATOR build path.
    ///
    /// Speculatively applies `op` to `self` and writes the resulting post-op
    /// `(balance, locked_balance)` of the deposit(s) `op` touches into its
    /// commitment field(s). This is the counterpart to the cosigner's
    /// verify-when-present check in `check_conformance`: the operator declares
    /// what it computes, the cosigner independently recomputes and compares —
    /// so `fill` MUST agree with `check` by construction (both derive balances
    /// from the same `apply`).
    ///
    /// Safe to call unconditionally under any ruleset (DEP-18): a correct
    /// commitment is conforming everywhere, and `compute_hash` hashes the raw
    /// message bytes, so a cosigner on older code re-derives the same
    /// content_hash while simply skipping the odd tags. Emitting commitments
    /// always means a later `QuorumUpgrade` to `balance-commit-v4` finds the
    /// require-presence rule already satisfied.
    ///
    /// Ops that touch no deposit, or that fail to apply (the caller will
    /// surface the same error at real commit time), are returned unchanged.
    pub fn fill_balance_commitments(
        &self,
        mut op: crate::messages::LedgerOperation,
    ) -> crate::messages::LedgerOperation {
        use crate::messages::{BalanceCommitment, LedgerOperation as Op};

        let next = match self.apply(&op) {
            Ok(n) => n,
            Err(_) => return op,
        };
        // Post-op pair for a deposit id; (0, 0) if the op removed it (close).
        let pair = |id: &DepositId| -> BalanceCommitment {
            let (balance_after, locked_after) = next
                .deposits
                .get(id)
                .map(|d| (d.balance, d.locked_balance))
                .unwrap_or((0, 0));
            BalanceCommitment {
                balance_after,
                locked_after,
            }
        };
        match &mut op {
            Op::DepositOpen {
                deposit_id,
                commitment,
                ..
            }
            | Op::DepositClose {
                deposit_id,
                commitment,
                ..
            }
            | Op::FeeCollect {
                deposit_id,
                commitment,
                ..
            }
            | Op::InvoiceCredit {
                deposit_id,
                commitment,
                ..
            }
            | Op::InvoiceLock {
                deposit_id,
                commitment,
                ..
            }
            | Op::InvoiceFail {
                deposit_id,
                commitment,
                ..
            }
            | Op::InvoiceFulfill {
                deposit_id,
                commitment,
                ..
            }
            | Op::OnchainCredit {
                deposit_id,
                commitment,
                ..
            }
            | Op::OnchainLock {
                deposit_id,
                commitment,
                ..
            }
            | Op::OnchainFail {
                deposit_id,
                commitment,
                ..
            }
            | Op::OnchainFulfill {
                deposit_id,
                commitment,
                ..
            } => {
                *commitment = Some(pair(deposit_id));
            }
            Op::TransferLock {
                source_deposit_id,
                commitment,
                ..
            } => {
                *commitment = Some(pair(source_deposit_id));
            }
            Op::TransferFail {
                transfer_id,
                commitment,
                ..
            } => {
                if let Some(pt) = self.pending_transfers.get(transfer_id) {
                    *commitment = Some(pair(&pt.source_deposit_id));
                }
            }
            Op::TransferComplete {
                transfer_id,
                commitment,
                dest_commitment,
                ..
            } => {
                if let Some(pt) = self.pending_transfers.get(transfer_id) {
                    *commitment = Some(pair(&pt.source_deposit_id));
                    *dest_commitment = Some(pair(&pt.destination_deposit_id));
                }
            }
            _ => {}
        }
        op
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
        //    verify_operator_signature()`, over the DEP-02 v2 operator
        //    digest (`SignedLedgerUpdate::operator_digest`).
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
                let derived =
                    Self::compute_ledger_id(&update.operator_id, &reserves_id, genesis_block);
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
        let ctx = ApplyCtx {
            height: update.block_height,
            seq: update.sequence_number,
            hash: update.chain_hash(),
        };
        let (mut next, violations) = with_apply_ctx(ctx, || {
            self.apply_with_verifier(&op, authorizer, update.block_height)
        })?;
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
        let ctx = ApplyCtx {
            height: current_height,
            seq: self.sequence + 1,
            hash: [0u8; 32],
        };
        match with_apply_ctx(ctx, || self.apply(operation)) {
            Ok(next) => next.check_conformance(operation, Some(self), authorizer, current_height),
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

        // DEP-05: obligations never exceed reserves. Collateral is not a cap on
        // credits; it is a floor on the vault's split, checked at QuorumBegin.
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
            LedgerOperation::QuorumBegin { .. } => {
                let floor_bps = crate::types::collateral_floor_bps(self.quorum_members.iter());
                if !crate::types::collateral_meets_floor(
                    self.reserves_amount,
                    self.collateral_amount,
                    floor_bps,
                ) {
                    violations.push(ConformanceViolation::CollateralBelowFloor {
                        reserves: self.reserves_amount,
                        collateral: self.collateral_amount,
                        floor_bps,
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
        // (nonce, expiry) pair into the set.
        //
        // The check needs the deposit's pre-state because apply() has already
        // inserted into seen_nonces by the time conformance runs; comparing against
        // post-state would always self-match. Without pre_state we skip the check
        // (it's available on every apply_with_verifier* / apply_signed* path).
        if let Some(pre) = pre_state {
            let (op_name, deposit_id, op_nonce, op_expiry) = match operation {
                LedgerOperation::InvoiceLock {
                    deposit_id,
                    nonce,
                    expiry,
                    ..
                } => ("InvoiceLock", Some(deposit_id), Some(*nonce), Some(*expiry)),
                LedgerOperation::OnchainLock {
                    deposit_id,
                    nonce,
                    expiry,
                    ..
                } => ("OnchainLock", Some(deposit_id), Some(*nonce), Some(*expiry)),
                LedgerOperation::TransferLock {
                    source_deposit_id,
                    nonce,
                    expiry,
                    ..
                } => (
                    "TransferLock",
                    Some(source_deposit_id),
                    Some(*nonce),
                    Some(*expiry),
                ),
                LedgerOperation::DepositKeyRotate {
                    deposit_id,
                    nonce,
                    expiry,
                    ..
                } => (
                    "DepositKeyRotate",
                    Some(deposit_id),
                    Some(*nonce),
                    Some(*expiry),
                ),
                LedgerOperation::ExitRequest {
                    deposit_id,
                    nonce,
                    expiry,
                    ..
                } => ("ExitRequest", Some(deposit_id), Some(*nonce), Some(*expiry)),
                LedgerOperation::ExitCancel {
                    deposit_id,
                    nonce,
                    expiry,
                    ..
                } => ("ExitCancel", Some(deposit_id), Some(*nonce), Some(*expiry)),
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
                    let nonce_replayed =
                        prev_deposit
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
            amount,
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
                    // Bound the amount: at most one assessment period is due
                    // (calculate_fees_due caps to a single frequency_blocks
                    // period). The operator may collect less, never more — this
                    // is what stops a years-of-backlog sweep or any over-bill
                    // beyond the depositor's accepted schedule. Version-gated
                    // (DEP-18): only ledgers upgraded to `fee-cap-v3` enforce it,
                    // so an upgraded node never retroactively faults a FeeCollect
                    // cosigned under an older ruleset.
                    if ruleset_enforces_fee_cap(&pre.active_ruleset_name) {
                        let max_due = deposit.calculate_fees_due(*block_height);
                        if *amount > max_due {
                            violations.push(ConformanceViolation::FeeExceedsAssessment {
                                collected: *amount,
                                max_due,
                            });
                        }
                    }
                }
            }
        }

        // QuorumUpgrade (DEP-18): an off-chain version bump may only move the
        // ledger to a known ruleset in the SAME reserves-cascade family — that
        // keeps the on-chain reserves UTXO valid without a rotation. A target in
        // a different family, or an unknown one, MUST use QuorumBegin instead.
        if let LedgerOperation::QuorumUpgrade {
            new_protocol_version,
        } = operation
        {
            if let Some(pre) = pre_state {
                if !ruleset_known(new_protocol_version) {
                    violations.push(ConformanceViolation::UnknownRuleset {
                        name: new_protocol_version.clone(),
                    });
                } else if reserves_family(new_protocol_version)
                    != reserves_family(&pre.active_ruleset_name)
                {
                    violations.push(ConformanceViolation::RulesetFamilyMismatch {
                        from: pre.active_ruleset_name.clone(),
                        to: new_protocol_version.clone(),
                    });
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
                // unsound — see the two carve-outs). Only the
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
            LedgerOperation::TransferLock {
                source_deposit_id, ..
            } => {
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
            LedgerOperation::ExitRequest { deposit_id, .. }
            | LedgerOperation::ExitCancel { deposit_id, .. } => {
                // DEP-20 §3: depositor-signed like any spend (DEP-17 op `spend`, kind exit/exit_cancel).
                if let Some(deposit) = self.deposits.get(deposit_id) {
                    if !authorizer.authorize(&deposit.descriptor, operation) {
                        violations.push(ConformanceViolation::InvalidWitness {
                            operation: if matches!(operation, LedgerOperation::ExitRequest { .. }) {
                                "ExitRequest"
                            } else {
                                "ExitCancel"
                            },
                            detail: "witness does not satisfy deposit descriptor".to_string(),
                        });
                    }
                }
            }
            LedgerOperation::DepositKeyRotate { deposit_id, .. } => {
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

        // ── Balance commitments (DEP-02 §Balance Commitments) ──────────────
        // Every balance-touching op may declare the post-op `(balance,
        // locked_balance)` of the deposit(s) it moves. `self` is the POST-apply
        // state, so the declared pair must equal `self.deposits[id]`'s pair
        // (or (0,0) when the op removed the deposit, i.e. DepositClose).
        //
        //   - verify-when-present: intrinsic to EVERY ruleset — a declared
        //     commitment that doesn't match the replay is always a violation.
        //   - require-presence: only under `balance-commit-v4`, every
        //     balance-touching op MUST carry its commitment(s).
        //
        // TransferComplete/TransferFail resolve their deposit_id(s) from the
        // pending-transfer entry in `pre_state` (apply() has already removed it
        // from post-state).
        {
            use crate::messages::{BalanceCommitment, LedgerOperation as Op};

            // (deposit_id, declared, op_label) triples this op is responsible for.
            let mut obligations: Vec<(DepositId, &Option<BalanceCommitment>, &'static str)> =
                Vec::new();
            match operation {
                Op::DepositOpen {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "DepositOpen")),
                Op::DepositClose {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "DepositClose")),
                Op::FeeCollect {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "FeeCollect")),
                Op::InvoiceCredit {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "InvoiceCredit")),
                Op::InvoiceLock {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "InvoiceLock")),
                Op::InvoiceFail {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "InvoiceFail")),
                Op::InvoiceFulfill {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "InvoiceFulfill")),
                Op::OnchainCredit {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "OnchainCredit")),
                Op::OnchainLock {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "OnchainLock")),
                Op::OnchainFail {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "OnchainFail")),
                Op::OnchainFulfill {
                    deposit_id,
                    commitment,
                    ..
                } => obligations.push((*deposit_id, commitment, "OnchainFulfill")),
                Op::TransferLock {
                    source_deposit_id,
                    commitment,
                    ..
                } => obligations.push((*source_deposit_id, commitment, "TransferLock")),
                Op::TransferFail {
                    transfer_id,
                    commitment,
                    ..
                } => {
                    if let Some(pt) = pre_state.and_then(|p| p.pending_transfers.get(transfer_id)) {
                        obligations.push((pt.source_deposit_id, commitment, "TransferFail"));
                    }
                }
                Op::TransferComplete {
                    transfer_id,
                    commitment,
                    dest_commitment,
                    ..
                } => {
                    if let Some(pt) = pre_state.and_then(|p| p.pending_transfers.get(transfer_id)) {
                        obligations.push((pt.source_deposit_id, commitment, "TransferComplete"));
                        obligations.push((
                            pt.destination_deposit_id,
                            dest_commitment,
                            "TransferComplete",
                        ));
                    }
                }
                _ => {}
            }

            let requires = ruleset_requires_balance_commitments(&self.active_ruleset_name);
            for (deposit_id, declared, label) in obligations {
                // Post-op pair; absent (removed by DepositClose) reads as (0, 0).
                let (actual_balance, actual_locked) = self
                    .deposits
                    .get(&deposit_id)
                    .map(|d| (d.balance, d.locked_balance))
                    .unwrap_or((0, 0));
                match declared {
                    Some(c) => {
                        if c.balance_after != actual_balance || c.locked_after != actual_locked {
                            violations.push(ConformanceViolation::BalanceCommitmentMismatch {
                                operation: label,
                                deposit_id: hex::encode(deposit_id),
                                declared_balance: c.balance_after,
                                declared_locked: c.locked_after,
                                actual_balance,
                                actual_locked,
                            });
                        }
                    }
                    None => {
                        if requires {
                            violations.push(ConformanceViolation::MissingBalanceCommitment {
                                operation: label,
                                deposit_id: hex::encode(deposit_id),
                            });
                        }
                    }
                }
            }
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
        self.total_deposit_balance
    }

    /// Ground-truth O(#deposits) fold over every deposit's balance. This is what
    /// the cached `total_deposit_balance` must always equal; used by
    /// `rebuild_balance_cache` and the debug-build drift assertion in
    /// `apply_in_place`. Not for hot paths — use `total_deposit_balance()`.
    pub fn fold_deposit_balance(&self) -> u64 {
        self.deposits
            .values()
            .fold(0u64, |acc, d| acc.saturating_add(d.balance))
    }

    /// Recompute the cached `total_deposit_balance` from the deposits map.
    /// Production never needs this (every balance mutation goes through
    /// `apply_in_place`, which keeps the cache in step), but code that builds a
    /// `LedgerState` by inserting deposits directly — tests, ad-hoc fixtures —
    /// must call it so the cache matches the map.
    pub fn rebuild_balance_cache(&mut self) {
        self.total_deposit_balance = self.fold_deposit_balance();
    }

    /// Adjust the cached total by the signed delta between a deposit's balance
    /// before and after a mutation. Centralizes the saturating-i128 arithmetic so
    /// every `apply_in_place` arm that touches a balance stays consistent.
    #[inline]
    fn add_balance_delta(&mut self, before: u64, after: u64) {
        let next = self.total_deposit_balance as i128 + after as i128 - before as i128;
        // Clamp to [0, u64::MAX] rather than truncating the downcast. Real msat
        // totals (≤ 21M BTC ≈ 2.1e18) never approach u64::MAX (1.8e19), so this
        // ceiling is unreachable in production — but clamping matches the
        // saturating semantics of `fold_deposit_balance` and avoids a silent
        // wrap-to-tiny-value if a pathological caller ever did overflow.
        self.total_deposit_balance = next.clamp(0, u64::MAX as i128) as u64;
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
        state.rebuild_balance_cache(); // direct insert bypasses apply_in_place
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
            timeout_height: None,
            fee: None,
            witness: DescriptorWitness::new(),
            commitment: None,
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

    fn invoice_lock_with_fee(
        did: [u8; 16],
        amount: u64,
        fee: Option<u64>,
        payment_id: [u8; 32],
    ) -> LedgerOperation {
        LedgerOperation::InvoiceLock {
            deposit_id: did,
            amount,
            payment_id,
            sequence_number: 1,
            nonce: 1,
            expiry: u32::MAX,
            timeout_height: None,
            fee,
            witness: DescriptorWitness::new(),
            commitment: None,
        }
    }

    /// Keep-the-spread: a successful invoice pay consumes amount+fee from the
    /// deposit and the fee lands in `fees_accumulated` (operator revenue; it
    /// paid the actual routing off-ledger and keeps the difference).
    #[test]
    fn invoice_fee_kept_on_fulfill() {
        let (state, did) = state_with_one_deposit(); // balance 1000
        let pid = [0x11u8; 32];

        let (s1, _) = apply(
            &state,
            &invoice_lock_with_fee(did, 800, Some(100), pid),
            100,
        );
        let d = &s1.deposits[&did];
        assert_eq!(d.balance, 1000, "lock doesn't move balance, only locks it");
        assert_eq!(d.available_balance(), 100, "800+100 locked out of 1000");

        let fulfill = LedgerOperation::InvoiceFulfill {
            deposit_id: did,
            amount: 800,
            payment_id: pid,
            sequence_number: 2,
            witness: DescriptorWitness::new(),
            preimage: [0u8; 32],
            commitment: None,
        };
        let (s2, _) = apply(&s1, &fulfill, 101);
        let d2 = &s2.deposits[&did];
        assert_eq!(d2.balance, 100, "1000 − amount(800) − fee(100)");
        assert_eq!(s2.fees_accumulated, 100, "operator keeps the fee budget");
    }

    /// On failure the full budget (amount+fee) is released; only the fixed dust
    /// fee is charged (no payment went out, so no routing was incurred).
    #[test]
    fn invoice_fee_released_on_fail() {
        let (state, did) = state_with_one_deposit(); // balance 1000, default fixed fee 2
        let pid = [0x22u8; 32];

        let (s1, _) = apply(
            &state,
            &invoice_lock_with_fee(did, 800, Some(100), pid),
            100,
        );
        let fail = LedgerOperation::InvoiceFail {
            deposit_id: did,
            payment_id: pid,
            sequence_number: 2,
            commitment: None,
        };
        let (s2, _) = apply(&s1, &fail, 101);
        let d = &s2.deposits[&did];
        assert_eq!(d.balance, 998, "only the fixed dust fee (2) is kept");
        assert_eq!(d.available_balance(), 998, "amount+fee fully released");
        assert_eq!(
            s2.fees_accumulated, 2,
            "fixed dust fee only; fee budget refunded"
        );
    }

    /// A first op against a fresh deposit (seen_nonces empty) is accepted; the
    /// (nonce, expiry) pair lands in seen_nonces for future replay checks.
    #[test]
    fn first_op_is_accepted_and_recorded() {
        let (state, did) = state_with_one_deposit();
        let op = invoice_lock(did, 50, [0xab; 32], 42, 1000);
        let (next, violations) = apply(&state, &op, 500);
        assert!(
            !violations.iter().any(|v| matches!(
                v,
                ConformanceViolation::NonceReplay { .. }
                    | ConformanceViolation::ExpiryPassed { .. }
            )),
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
            violations
                .iter()
                .any(|v| matches!(v, ConformanceViolation::NonceReplay { actual: 42, .. })),
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
                idx,
                nonce,
                violations,
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
            commitment: None,
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

#[cfg(test)]
mod balance_cache_tests {
    //! `total_deposit_balance` is a cache maintained incrementally by
    //! `apply_in_place`. The debug_assert at the end of `apply_in_place` already
    //! checks cache == fold on every apply across the whole suite; these tests
    //! additionally pin the *value* (the accessor returns the right number) and
    //! that it tracks across credit / transfer / close.
    use super::*;
    use crate::messages::LedgerOperation;

    fn pk() -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    fn open(state: &mut LedgerState, did: [u8; 16]) {
        state
            .apply_in_place(&LedgerOperation::DepositOpen {
                deposit_id: did,
                descriptor: format!("d{}", did[0]),
                fees: None,
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
                commitment: None,
            })
            .unwrap();
    }

    fn credit(state: &mut LedgerState, did: [u8; 16], hash: u8, amount: u64) {
        state
            .apply_in_place(&LedgerOperation::InvoiceCredit {
                payment_hash: [hash; 32],
                deposit_id: did,
                amount,
                invoice_id: format!("i{}", hash),
                sequence_number: 0,
                wallet_authorization: None,
                commitment: None,
            })
            .unwrap();
    }

    #[test]
    fn cache_tracks_credits_and_close_and_equals_fold() {
        let mut state = LedgerState::new(pk(), "r".to_string(), 0);
        assert_eq!(state.total_deposit_balance(), 0);

        let a = [1u8; 16];
        let b = [2u8; 16];
        open(&mut state, a);
        open(&mut state, b);
        assert_eq!(state.total_deposit_balance(), 0);

        credit(&mut state, a, 0xa1, 500);
        credit(&mut state, b, 0xb1, 300);
        credit(&mut state, a, 0xa2, 200);
        // 500 + 200 on a, 300 on b
        assert_eq!(state.total_deposit_balance(), 1000);
        assert_eq!(state.total_deposit_balance(), state.fold_deposit_balance());

        // A zero-balance deposit can be closed; total is unchanged.
        let c = [3u8; 16];
        open(&mut state, c);
        state
            .apply_in_place(&LedgerOperation::DepositClose {
                deposit_id: c,
                commitment: None,
            })
            .unwrap();
        assert_eq!(state.total_deposit_balance(), 1000);
        assert_eq!(state.total_deposit_balance(), state.fold_deposit_balance());
    }

    #[test]
    fn rebuild_matches_fold_after_direct_insert() {
        let mut state = LedgerState::new(pk(), "r".to_string(), 0);
        let mut d = Deposit::new("x".to_string(), None);
        d.balance = 777;
        let did = d.deposit_id;
        state.deposits.insert(did, d); // bypasses apply_in_place
        assert_eq!(
            state.total_deposit_balance(),
            0,
            "cache stale before rebuild"
        );
        state.rebuild_balance_cache();
        assert_eq!(state.total_deposit_balance(), 777);
        assert_eq!(state.total_deposit_balance(), state.fold_deposit_balance());
    }

    #[test]
    fn quorum_begin_ref_defaults_none_then_stamps() {
        let mut state = LedgerState::new(pk(), "rid".into(), 100);
        assert_eq!(state.quorum_begin_block, None);
        assert_eq!(state.quorum_begin_sequence, None);
        assert_eq!(state.quorum_begin_hash, None);
        state.note_quorum_begin(120, 5, [9u8; 32]);
        assert_eq!(state.quorum_begin_block, Some(120));
        assert_eq!(state.quorum_begin_sequence, Some(5));
        assert_eq!(state.quorum_begin_hash, Some([9u8; 32]));
        // With expiry set, this is what the hub renders as duration.
        state.quorum_expiry = Some(1020);
        let duration = state.quorum_expiry.unwrap() - state.quorum_begin_block.unwrap();
        assert_eq!(duration, 900);
    }
}
