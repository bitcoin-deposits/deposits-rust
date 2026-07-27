// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Conformance checking types and traits.

// ============================================================================
// Conformance Checking
// ============================================================================

/// A violation of protocol conformance rules detected in a ledger state.
///
/// Conformance violations indicate the operator has produced a valid state
/// transition (the operation was applied) but the resulting state violates
/// protocol rules. Quorum members use these to detect misbehavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConformanceViolation {
    /// Total deposit balances exceed declared reserves.
    InsufficientReserves { reserves: u64, obligations: u64 },

    /// A witness or signature failed verification.
    InvalidWitness {
        operation: &'static str,
        detail: String,
    },

    /// Lock-class operation (InvoiceLock/OnchainLock/TransferLock) had
    /// `amount == 0`. Zero-amount locks have no semantic purpose and
    /// would silently succeed against the state-machine apply, so
    /// conformance treats them as a hard refusal.
    ZeroAmount { operation: &'static str },

    /// OnchainLock's `destination_address` was empty.
    EmptyDestination,

    /// DepositKeyRotate's `new_descriptor` failed to parse as a
    /// miniscript descriptor. Without rejecting at rotation time the
    /// resulting deposit becomes unspendable through normal paths.
    UnparseableDescriptor {
        operation: &'static str,
        detail: String,
    },

    /// Credit-class operation (InvoiceCredit/OnchainCredit/
    /// TransferComplete) would push total credited balances above the
    /// active quorum's collateral envelope. Separate from
    /// InsufficientReserves: reserves cap absolute custody, collateral
    /// caps the share an under-collateralised operator can route.
    ExceedsCollateral { credit: u64, collateral: u64 },

    /// FeeCollect fired before the deposit's fee window elapsed.
    /// Operators can't accelerate fee assessment past the
    /// `frequency_blocks` cadence the depositor accepted at open.
    FeeWindowNotElapsed {
        current_block: u32,
        next_allowed_block: u32,
    },

    /// FeeCollect tried to take more than one assessment period's worth of
    /// custody fee. The amount must not exceed `calculate_fees_due` for the
    /// pre-state deposit at the op's block height — which is itself capped to a
    /// single `frequency_blocks` period. This bounds the operator: it can never
    /// sweep years of backlog (the block-0 accrual bug) or otherwise over-bill
    /// a deposit beyond the schedule the depositor accepted at open.
    FeeExceedsAssessment {
        collected: u64,
        max_due: u64,
    },

    /// QuorumUpgrade (DEP-18) named a ruleset this implementation doesn't know.
    UnknownRuleset { name: String },

    /// A balance-touching op declared a post-op `(balance, locked_balance)`
    /// commitment (DEP-02 §Balance Commitments) that does not equal the
    /// replayed post-state for that deposit. Intrinsic to every ruleset,
    /// including `legacy`: a present-but-wrong commitment is always a
    /// conformance break (an honest operator declares the truth). The
    /// verify-when-present half of the rule.
    BalanceCommitmentMismatch {
        operation: &'static str,
        /// Hex deposit_id the commitment is for (primary or, for a transfer,
        /// the destination).
        deposit_id: String,
        declared_balance: u64,
        declared_locked: u64,
        actual_balance: u64,
        actual_locked: u64,
    },

    /// A balance-touching op omitted its required commitment under a ruleset
    /// that mandates them (`balance-commit-v4`; DEP-02 §Balance Commitments).
    /// The require-presence half of the rule — dormant on `legacy` /
    /// `fee-cap-v3`, where commitment-less ops stay conforming.
    MissingBalanceCommitment {
        operation: &'static str,
        /// Hex deposit_id whose commitment is missing.
        deposit_id: String,
    },

    /// QuorumUpgrade (DEP-18) tried to move to a ruleset in a different
    /// reserves-cascade family. That changes the on-chain reserves script, so it
    /// requires a QuorumBegin (reserves rotation), not an off-chain upgrade.
    RulesetFamilyMismatch { from: String, to: String },

    /// DepositOpen's `descriptor` exceeded the active quorum's
    /// `max_descriptor_bytes` policy. Without this, an outsized
    /// descriptor could bloat every cosigner's signing path.
    DescriptorTooLarge { actual: usize, max: u32 },

    /// A signature-bearing op (InvoiceLock / OnchainLock / TransferLock /
    /// DepositKeyRotate) supplied a `nonce` already present in the deposit's
    /// `seen_nonces`. Replay protection for the dep-16 operation preimage: the
    /// same nonce can be reused once `current_height` has passed every expiry
    /// the nonce was ever paired with (`ExpiryPassed` catches the original
    /// signed op in that case, so reuse is safe).
    NonceReplay {
        operation: &'static str,
        actual: u64,
    },

    /// A signature-bearing op supplied an `expiry` block height that the
    /// chain has already buried. Signatures over the dep-16 operation
    /// preimage bind to a specific expiry; the protocol rejects after that
    /// height regardless of any other signal.
    ExpiryPassed {
        operation: &'static str,
        expiry: u32,
        current_height: u32,
    },

    /// A protocol rule was violated.
    ProtocolRule { rule: &'static str, detail: String },

    /// The state machine itself refused the transition (invariant
    /// failure, unknown deposit id, etc.) — surfaced through the
    /// conformance API by `check_speculative` so callers don't have
    /// to branch on `apply` errors separately. Carries the inner
    /// error's debug rendering.
    StateMachineRejected { detail: String },
}

impl std::fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientReserves {
                reserves,
                obligations,
            } => write!(f, "reserves ({}) < obligations ({})", reserves, obligations),
            Self::InvalidWitness { operation, detail } => {
                write!(f, "invalid witness in {}: {}", operation, detail)
            }
            Self::ZeroAmount { operation } => {
                write!(f, "zero amount in {}", operation)
            }
            Self::EmptyDestination => write!(f, "empty destination address"),
            Self::UnparseableDescriptor { operation, detail } => write!(
                f,
                "unparseable descriptor in {}: {}",
                operation, detail
            ),
            Self::ExceedsCollateral { credit, collateral } => write!(
                f,
                "credit ({}) would exceed quorum collateral ({})",
                credit, collateral
            ),
            Self::FeeWindowNotElapsed {
                current_block,
                next_allowed_block,
            } => write!(
                f,
                "fee_collect at block {} fires before next allowed assessment at block {}",
                current_block, next_allowed_block,
            ),
            Self::FeeExceedsAssessment { collected, max_due } => write!(
                f,
                "fee_collect amount {} exceeds the one-period assessment due ({})",
                collected, max_due,
            ),
            Self::UnknownRuleset { name } => {
                write!(f, "quorum_upgrade names unknown ruleset {:?}", name)
            }
            Self::RulesetFamilyMismatch { from, to } => write!(
                f,
                "quorum_upgrade {:?}->{:?} changes reserves-cascade family (use quorum_begin)",
                from, to,
            ),
            Self::DescriptorTooLarge { actual, max } => write!(
                f,
                "descriptor size {} bytes exceeds quorum max of {} bytes",
                actual, max
            ),
            Self::NonceReplay { operation, actual } => write!(
                f,
                "{}: nonce {} already accepted on this deposit within an unexpired window",
                operation, actual,
            ),
            Self::ExpiryPassed {
                operation,
                expiry,
                current_height,
            } => write!(
                f,
                "{}: expiry block {} ≤ current height {}",
                operation, expiry, current_height,
            ),
            Self::ProtocolRule { rule, detail } => {
                write!(f, "protocol rule '{}' violated: {}", rule, detail)
            }
            Self::StateMachineRejected { detail } => {
                write!(f, "state machine refused transition: {}", detail)
            }
            Self::BalanceCommitmentMismatch {
                operation,
                deposit_id,
                declared_balance,
                declared_locked,
                actual_balance,
                actual_locked,
            } => write!(
                f,
                "{}: balance commitment for deposit {} declared ({}, {}) but replayed state is ({}, {})",
                operation,
                &deposit_id[..deposit_id.len().min(16)],
                declared_balance,
                declared_locked,
                actual_balance,
                actual_locked,
            ),
            Self::MissingBalanceCommitment {
                operation,
                deposit_id,
            } => write!(
                f,
                "{}: missing required balance commitment for deposit {} (balance-commit-v4)",
                operation,
                &deposit_id[..deposit_id.len().min(16)],
            ),
        }
    }
}

/// Authorization surface for descriptor evaluation. The protocol layer
/// declares the trait; deposits-core's `Dep16Authorizer` provides the real
/// impl via the dep-16 calculus (descriptor → typed operation → ledger state
/// → keyed witness → verdict).
///
/// The message a signature commits to is the dep-17 operation preimage. The
/// witness is interpreted in the dep-16 keyed sense (signatures keyed by
/// pubkey, preimages by hash) rather than as a positional byte stack.
/// Descriptor evaluation can read ledger state via the dep-16 LedgerState
/// surface rather than only timelock-vs-height.
pub trait Authorizer {
    /// Authorize an operation by evaluating its dep-16 form against the named
    /// descriptor. Returns `true` iff the operation's embedded witness
    /// satisfies the descriptor's policy.
    ///
    /// The descriptor argument is explicit (rather than read from the deposit
    /// in `state`) so callers can authorize a modification against a pre-state
    /// descriptor — `DepositKeyRotate` authorizes against the *old* descriptor
    /// while `apply()` is mid-flight installing the new one.
    fn authorize(
        &self,
        descriptor: &str,
        operation: &crate::messages::LedgerOperation,
    ) -> bool;

    /// Parse-check a descriptor string, returning `None` if parseable and
    /// `Some(detail)` otherwise. Used to fail unparseable descriptors at
    /// admission rather than at first authorization. Default accepts
    /// everything.
    fn validate_descriptor(&self, descriptor: &str) -> Option<String> {
        let _ = descriptor;
        None
    }
}

/// `Authorizer` that authorizes nothing — every call returns `false`. Useful
/// as a placeholder in tests where descriptor authorization should fail
/// uniformly.
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn authorize(&self, _: &str, _: &crate::messages::LedgerOperation) -> bool {
        false
    }
}

/// `Authorizer` that authorizes everything — for protocol-layer tests that
/// don't need cryptographic authorization.
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _: &str, _: &crate::messages::LedgerOperation) -> bool {
        true
    }
}
