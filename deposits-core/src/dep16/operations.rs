// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Translation layer: protocol-side `LedgerOperation` → dep-16 [`Operation`].
//!
//! Each `LedgerOperation` variant the descriptor evaluates against is translated into a dep-16
//! [`OperationData`] carrying the args a descriptor's `match(operation_type(), branch(<sym>, …))`
//! can dispatch on. The descriptor sees three op_types — `spend`, `receive`, `update` — chosen
//! by the translation, with rail-specific details exposed as named args (and `kind` as an opt-in
//! spend-side discriminator). Variants that aren't descriptor-evaluated (`InvoiceFulfill`,
//! `OnchainFulfill`, administrative ops) translate to `None`.
//!
//! See PLAN-dep16-integration.md §"What the descriptor sees" for the design. This phase covers
//! the mapping for variants the protocol already has fields for; variants needing protocol
//! changes (uniform per-deposit nonce + `expiry`, the `DepositDescriptorUpdate` rename, the
//! `release_descriptor` arg in `TransferLock`) are marked with explicit TODOs and carry
//! placeholder values where required.

use std::collections::BTreeMap;

use bitcoin::PublicKey;
use deposits_protocol::messages::LedgerOperation;

use super::{OperationData, Symbol, Value};

/// The descriptor op_type symbols the calculus sees. The full set is intentionally small —
/// templates and raw descriptors dispatch on these via `match(operation_type(), branch(<sym>, …))`.
pub mod op_type {
    /// Outbound value movement (invoice payment, on-chain withdrawal, internal transfer). The
    /// rail-specific distinction is exposed as the `kind` arg, optional to dispatch on.
    pub const SPEND: &str = "spend";
    /// Incoming value movement requiring authorization (a transfer into a deposit whose
    /// `receive_requires_sig=true`).
    pub const RECEIVE: &str = "receive";
    /// Descriptor modification (replace / insert / delete at an ast path).
    pub const UPDATE: &str = "update";
}

/// Spend-kind discriminator passed as the `kind` arg. Optional gating for descriptors that want
/// to distinguish by rail; the everyday descriptor ignores it and writes a single
/// `branch(spend, prove(pk(K)))`.
pub mod kind {
    pub const INVOICE: &str = "invoice";
    pub const ONCHAIN: &str = "onchain";
    pub const TRANSFER: &str = "transfer";
}

/// Translate a protocol-side [`LedgerOperation`] into the dep-16 [`OperationData`] the
/// descriptor evaluates against. Returns `None` for variants that don't go through descriptor
/// evaluation (`InvoiceFulfill`, `OnchainFulfill`, administrative ops, etc.).
///
/// The returned [`OperationData`] is what the dep-16 evaluator consumes as its `Operation`. Its
/// canonical encoding (the *operation preimage*) is what witness signatures verify against —
/// see [`super::operation_preimage`] for the bytes and [`miniscript::calculus::operation_sighash`]
/// for the tagged hash.
///
/// # Phase-2 limitations
///
/// - `nonce` is the variant's existing sequence-style field where available (e.g. `InvoiceLock`'s
///   `sequence_number`) and `0` otherwise, pending the uniform per-deposit nonce that Phase 3
///   adds.
/// - `expiry` is `u32::MAX` (never expires) until Phase 3 adds the field to the carrying
///   variants.
/// - `DepositKeyRotate` is mapped as `update`, but it stays under its current variant name and
///   uses today's whole-descriptor-replacement semantics. The `DepositDescriptorUpdate` rename
///   and the dep-16-modification-primitive `(sub_op, path, subtree-or-key)` shape land in
///   Phase 4.
/// - `TransferComplete` carries a witness for the lock's release descriptor, but the
///   `release_descriptor` arg doesn't exist on `TransferLock` yet (Phase 5). For now,
///   `TransferComplete` translates to `None` to flag that the release-side evaluation isn't
///   wired up; the operation-preimage construction for it lands when `TransferLock` carries the
///   release descriptor.
pub fn to_dep16(op: &LedgerOperation) -> Option<OperationData<PublicKey>> {
    match op {
        // ----- spend rails -----------------------------------------------------------------
        LedgerOperation::InvoiceLock {
            deposit_id,
            amount,
            payment_id,
            nonce,
            expiry,
            ..
        } => Some(OperationData {
            op_type: Symbol::new(op_type::SPEND),
            args: {
                let mut a = BTreeMap::new();
                a.insert("amount".to_string(), Value::Int(*amount as i128));
                a.insert("kind".to_string(), Value::Symbol(Symbol::new(kind::INVOICE)));
                a.insert("payment_id".to_string(), Value::Bytes(payment_id.to_vec()));
                a
            },
            deposit_id: pad_deposit_id(deposit_id),
            nonce: *nonce,
            expiry: *expiry,
        }),

        LedgerOperation::OnchainLock {
            deposit_id,
            amount,
            fee_sats,
            destination_address,
            withdrawal_id,
            nonce,
            expiry,
            ..
        } => Some(OperationData {
            op_type: Symbol::new(op_type::SPEND),
            args: {
                let mut a = BTreeMap::new();
                a.insert("amount".to_string(), Value::Int(*amount as i128));
                a.insert("destination".to_string(), Value::Bytes(destination_address.as_bytes().to_vec()));
                a.insert("fee".to_string(), Value::Int(*fee_sats as i128));
                a.insert("kind".to_string(), Value::Symbol(Symbol::new(kind::ONCHAIN)));
                a.insert("withdrawal_id".to_string(), Value::Bytes(withdrawal_id.to_vec()));
                a
            },
            deposit_id: pad_deposit_id(deposit_id),
            nonce: *nonce,
            expiry: *expiry,
        }),

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
        } => Some(OperationData {
            op_type: Symbol::new(op_type::SPEND),
            args: {
                let mut a = BTreeMap::new();
                a.insert("amount".to_string(), Value::Int(*amount as i128));
                a.insert("completion_script".to_string(), Value::Bytes(completion_script.as_bytes().to_vec()));
                a.insert("destination_deposit_id".to_string(), Value::Bytes(destination_deposit_id.to_vec()));
                a.insert("fee".to_string(), Value::Int(*fee as i128));
                a.insert("kind".to_string(), Value::Symbol(Symbol::new(kind::TRANSFER)));
                // The transfer-level nonce is the 32-byte transfer-identity field, distinct
                // from `nonce` above which is the per-deposit monotonic counter dep-16 binds
                // into the operation preimage.
                a.insert("transfer_nonce".to_string(), Value::Bytes(transfer_nonce.to_vec()));
                a.insert("transfer_id".to_string(), Value::Bytes(transfer_id.to_vec()));
                a.insert("timeout_height".to_string(), Value::Int(*timeout_height as i128));
                // TODO phase 5: include `release_descriptor` here once TransferLock carries it
                a
            },
            deposit_id: pad_deposit_id(source_deposit_id),
            nonce: *nonce,
            expiry: *expiry,
        }),

        // ----- modification ----------------------------------------------------------------
        LedgerOperation::DepositKeyRotate {
            deposit_id,
            new_descriptor,
            nonce,
            expiry,
            ..
        } => Some(OperationData {
            op_type: Symbol::new(op_type::UPDATE),
            args: {
                let mut a = BTreeMap::new();
                // Phase 4 reshapes this variant into DepositDescriptorUpdate carrying (sub_op,
                // path, subtree-or-key). For now, the whole-descriptor-replacement form maps to
                // a "replace at body root" — the candidate descriptor source is the new arg.
                a.insert("sub_op".to_string(), Value::Symbol(Symbol::new("replace")));
                a.insert(
                    "new_descriptor_source".to_string(),
                    Value::Bytes(new_descriptor.as_bytes().to_vec()),
                );
                a
            },
            deposit_id: pad_deposit_id(deposit_id),
            nonce: *nonce,
            expiry: *expiry,
        }),

        // ----- transfer release -----------------------------------------------------------
        // TransferComplete authorizes against the lock's completion_script (the release
        // descriptor specified at TransferLock time), not the primary deposit descriptor.
        // The dep-16 Operation here carries the transfer_id (so the lock's completion_script
        // is the right thing to look up) plus the script_witness's own evidence. The
        // conformance check in deposits-protocol pulls the completion_script from
        // pre_state.pending_transfers and feeds (descriptor, this Operation) to the
        // Authorizer. No nonce / expiry — TransferComplete is identified by transfer_id;
        // replay is prevented by the lock being removed from pending_transfers on apply.
        LedgerOperation::TransferComplete { transfer_id, .. } => Some(OperationData {
            op_type: Symbol::new("transfer_release"),
            args: {
                let mut a = BTreeMap::new();
                a.insert("transfer_id".to_string(), Value::Bytes(transfer_id.to_vec()));
                a
            },
            // The deposit_id binding for TransferComplete is the transfer_id (which is what
            // distinguishes this release across the operator's pending transfers); we put
            // the transfer_id bytes into the deposit_id slot for replay-domain separation.
            deposit_id: *transfer_id,
            nonce: 0,
            expiry: u32::MAX,
        }),

        // ----- no descriptor evaluation ----------------------------------------------------
        // Operator-side fulfillment of locks. Authorization for the *lock* already ran (against
        // the source deposit's descriptor); the fulfill is just the operator confirming the
        // lock's release condition was met (preimage for invoice, chain-watcher confirmation
        // for onchain). Re-evaluating the deposit's descriptor at fulfill time is unsound —
        // see PLAN's "two carve-outs" subsection.
        LedgerOperation::InvoiceFulfill { .. } => None,
        LedgerOperation::OnchainFulfill { .. } => None,

        // All other variants — ledger establishment, quorum management, fee bookkeeping,
        // disputes, credits, fails — don't go through descriptor evaluation in v1. They have
        // their own protocol-level authorization (operator signature, cosigner signature,
        // hash-chain position) but no descriptor to match.
        _ => None,
    }
}

/// Compute the operation preimage's tagged sighash for a [`LedgerOperation`] that goes through
/// descriptor evaluation. Returns `None` for variants that don't.
///
/// The returned 32 bytes are what signatures over this operation are verified against under the
/// dep-16 evaluator — see [`miniscript::calculus::operation_sighash`].
pub fn operation_sighash(op: &LedgerOperation) -> Option<[u8; 32]> {
    let dep16_op = to_dep16(op)?;
    let preimage = miniscript::calculus::operation_preimage(&dep16_op);
    Some(miniscript::calculus::operation_sighash(&preimage))
}

/// Build a synthetic dep-16 [`OperationData`] for a receive authorization. No corresponding
/// [`LedgerOperation`] variant exists — receives gate inbound value movement at admission time
/// (invoice/offer creation, transfer-release destination) rather than producing a state-machine
/// op, so the operation is built in-memory only by both wallet (for signing) and node (for
/// verification).
///
/// Wire-format coordination point with wallets: the wallet computes
/// `operation_sighash(receive_op(...))` and produces a signature over it. The wallet sends
/// `{ nonce, expiry, signatures: [...] }`. The node calls
/// [`receive_op`] with the same `(deposit_id, nonce, expiry, transfer_id)` and verifies each
/// signature against the resulting preimage via [`crate::dep16::Dep16Authorizer::authorize_receive`].
///
/// Args carried:
/// - When `transfer_id` is `Some`: receive is the destination side of a transfer; the
///   `transfer_id` lands in args so the wallet's signature binds to this specific transfer
///   (not just "any receive to this deposit").
/// - When `transfer_id` is `None`: receive is the admission-time gate on an invoice/offer;
///   args are empty.
pub fn receive_op(
    deposit_id: &deposits_protocol::types::DepositId,
    nonce: u64,
    expiry: u32,
    transfer_id: Option<&[u8]>,
) -> OperationData<PublicKey> {
    let mut args = BTreeMap::new();
    if let Some(t) = transfer_id {
        args.insert("transfer_id".to_string(), Value::Bytes(t.to_vec()));
    }
    OperationData {
        op_type: Symbol::new(op_type::RECEIVE),
        args,
        deposit_id: pad_deposit_id(deposit_id),
        nonce,
        expiry,
    }
}

/// Tagged-hash sighash of a [`receive_op`]. The bytes wallets sign to authorize a receive.
pub fn receive_op_sighash(
    deposit_id: &deposits_protocol::types::DepositId,
    nonce: u64,
    expiry: u32,
    transfer_id: Option<&[u8]>,
) -> [u8; 32] {
    let op = receive_op(deposit_id, nonce, expiry, transfer_id);
    let preimage = miniscript::calculus::operation_preimage(&op);
    miniscript::calculus::operation_sighash(&preimage)
}

/// Zero-extend a 16-byte [`DepositId`](deposits_protocol::types::DepositId) into the 32-byte
/// `deposit_id` dep-16's [`OperationData`] expects. The protocol's DepositId is itself derived
/// from `SHA256(descriptor)[..16]`, so the zero-padding preserves uniqueness; phase 6 can revisit
/// whether dep-16's deposit_id should be the full SHA256 instead of a zero-extended id.
fn pad_deposit_id(id: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use deposits_protocol::types::DescriptorWitness;

    fn dummy_deposit_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xde;
        id[1] = 0xad;
        id
    }

    /// `InvoiceLock` translates to a `spend` op with `kind=invoice` and the three args a
    /// descriptor can match on. The variant's `nonce` field (phase 3) becomes the dep-16 nonce.
    #[test]
    fn invoice_lock_maps_to_spend_with_kind_invoice() {
        let op = LedgerOperation::InvoiceLock {
            deposit_id: dummy_deposit_id(),
            amount: 50_000,
            payment_id: [0xab; 32],
            sequence_number: 3, // ledger-position bookkeeping; distinct from nonce
            nonce: 7,
            expiry: 1_000_000,
            witness: DescriptorWitness::new(),
        };
        let d = to_dep16(&op).expect("descriptor-evaluated");
        assert_eq!(d.op_type.as_str(), op_type::SPEND);
        assert_eq!(d.nonce, 7);
        assert_eq!(d.expiry, 1_000_000);
        assert_eq!(d.args["amount"], Value::Int(50_000));
        assert_eq!(d.args["kind"], Value::Symbol(Symbol::new(kind::INVOICE)));
        assert_eq!(d.args["payment_id"], Value::Bytes(vec![0xab; 32]));
    }

    /// `OnchainLock` translates to a `spend` op with `kind=onchain` and the destination/amount/
    /// fee/withdrawal_id args. The destination is the raw bytes of the address string (no
    /// parsing) — descriptors that gate on it compare bytes.
    #[test]
    fn onchain_lock_maps_to_spend_with_kind_onchain() {
        let op = LedgerOperation::OnchainLock {
            deposit_id: dummy_deposit_id(),
            amount: 100_000,
            fee_sats: 500,
            destination_address: "bc1qexample".to_string(),
            withdrawal_id: [0xcd; 32],
            nonce: 4,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let d = to_dep16(&op).expect("descriptor-evaluated");
        assert_eq!(d.op_type.as_str(), op_type::SPEND);
        assert_eq!(d.nonce, 4);
        assert_eq!(d.args["kind"], Value::Symbol(Symbol::new(kind::ONCHAIN)));
        assert_eq!(d.args["amount"], Value::Int(100_000));
        assert_eq!(d.args["fee"], Value::Int(500));
        assert_eq!(d.args["destination"], Value::Bytes(b"bc1qexample".to_vec()));
        assert_eq!(d.args["withdrawal_id"], Value::Bytes(vec![0xcd; 32]));
    }

    /// `TransferLock` translates to a `spend` op with `kind=transfer`. The transfer-level
    /// `transfer_nonce: [u8;32]` is distinct from the per-deposit dep-16 `nonce: u64` and is
    /// exposed as `transfer_nonce` arg so descriptors can match on it.
    #[test]
    fn transfer_lock_maps_to_spend_with_kind_transfer() {
        let op = LedgerOperation::TransferLock {
            transfer_nonce: [0x01; 32],
            source_deposit_id: dummy_deposit_id(),
            destination_deposit_id: [0xff; 16],
            amount: 25_000,
            fee: 100,
            completion_script: "tr(K)".to_string(),
            timeout_height: 900_000,
            transfer_id: [0x42; 32],
            nonce: 11,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let d = to_dep16(&op).expect("descriptor-evaluated");
        assert_eq!(d.op_type.as_str(), op_type::SPEND);
        assert_eq!(d.nonce, 11);
        assert_eq!(d.args["kind"], Value::Symbol(Symbol::new(kind::TRANSFER)));
        assert_eq!(d.args["amount"], Value::Int(25_000));
        assert_eq!(d.args["fee"], Value::Int(100));
        assert_eq!(d.args["timeout_height"], Value::Int(900_000));
        assert_eq!(d.args["transfer_nonce"], Value::Bytes(vec![0x01; 32]));
        assert_eq!(d.args["transfer_id"], Value::Bytes(vec![0x42; 32]));
        // Destination deposit id is 16 bytes (no zero-extension here — it's an arg, not the
        // dep-16 deposit_id field).
        assert_eq!(
            d.args["destination_deposit_id"],
            Value::Bytes(vec![0xff; 16])
        );
    }

    /// `DepositKeyRotate` translates to an `update` op. Today's whole-descriptor-replacement
    /// shape maps to a `sub_op=replace` with the candidate descriptor source as an arg; phase 4
    /// reshapes this into the dep-16-modification-primitive `(sub_op, path, subtree-or-key)`.
    #[test]
    fn deposit_key_rotate_maps_to_update_replace() {
        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: "wsh(prove(pk(02aa...)))".to_string(),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let d = to_dep16(&op).expect("descriptor-evaluated");
        assert_eq!(d.op_type.as_str(), op_type::UPDATE);
        assert_eq!(d.args["sub_op"], Value::Symbol(Symbol::new("replace")));
        assert!(matches!(
            d.args.get("new_descriptor_source"),
            Some(Value::Bytes(_))
        ));
    }

    /// Fulfill variants (InvoiceFulfill, OnchainFulfill) don't go through descriptor
    /// evaluation. Mapping returns `None`; the caller doesn't have an operation to
    /// evaluate against. (`TransferComplete` maps differently — it has its own release
    /// descriptor — and is covered by `transfer_complete_maps_to_transfer_release`.)
    #[test]
    fn fulfill_variants_skip_descriptor_evaluation() {
        let invoice_fulfill = LedgerOperation::InvoiceFulfill {
            deposit_id: dummy_deposit_id(),
            amount: 50_000,
            payment_id: [0xab; 32],
            sequence_number: 7,
            preimage: [0xff; 32],
            witness: DescriptorWitness::new(),
        };
        assert!(to_dep16(&invoice_fulfill).is_none());

        let onchain_fulfill = LedgerOperation::OnchainFulfill {
            deposit_id: dummy_deposit_id(),
            withdrawal_id: [0xcd; 32],
            amount: 100_000,
            txid: [0xfe; 32],
            destination_address: "bc1qexample".to_string(),
        };
        assert!(to_dep16(&onchain_fulfill).is_none());
    }

    /// `TransferComplete` translates to a `transfer_release` op so the lock's
    /// `completion_script` (the release descriptor specified at lock time) can be
    /// evaluated against the operation. The deposit_id slot carries the transfer_id —
    /// it's what distinguishes which release this is across pending transfers, and
    /// gives the dep-17 preimage the domain separation `deposit_id` provides for the
    /// other variants.
    #[test]
    fn transfer_complete_maps_to_transfer_release() {
        let op = LedgerOperation::TransferComplete {
            transfer_id: [0x42; 32],
            script_witness: DescriptorWitness::new(),
        };
        let d = to_dep16(&op).expect("descriptor-evaluated");
        assert_eq!(d.op_type.as_str(), "transfer_release");
        assert_eq!(d.args["transfer_id"], Value::Bytes(vec![0x42; 32]));
        assert_eq!(d.deposit_id, [0x42; 32]);
    }

    /// Administrative ops (no descriptor evaluation) translate to `None`. Spot-check
    /// `DepositClose` — operator-authorized, no descriptor involved.
    #[test]
    fn administrative_ops_skip_descriptor_evaluation() {
        let close = LedgerOperation::DepositClose {
            deposit_id: dummy_deposit_id(),
        };
        assert!(to_dep16(&close).is_none());
    }

    /// Two operations differing in args produce distinct operation preimages (and therefore
    /// distinct sighashes). This is the protocol-level replay/binding property dep-17's canonical
    /// encoding guarantees; this test exercises it through the translation layer.
    #[test]
    fn distinct_operations_produce_distinct_sighashes() {
        let common = (dummy_deposit_id(), [0xab; 32]);
        let op_a = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: 50_000,
            payment_id: common.1,
            sequence_number: 1,
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let op_b = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: 60_000, // changed
            payment_id: common.1,
            sequence_number: 1,
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let sh_a = operation_sighash(&op_a).expect("sighash");
        let sh_b = operation_sighash(&op_b).expect("sighash");
        assert_ne!(sh_a, sh_b, "different amounts → different sighashes");
    }

    /// Two operations differing only in `nonce` produce distinct sighashes — replay protection:
    /// an old signed operation can't be replayed with a future nonce because the preimage
    /// embeds the nonce.
    #[test]
    fn distinct_nonces_produce_distinct_sighashes() {
        let common = (dummy_deposit_id(), [0xab; 32], 50_000u64);
        let op_a = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: common.2,
            payment_id: common.1,
            sequence_number: 1,
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let op_b = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: common.2,
            payment_id: common.1,
            sequence_number: 1,
            nonce: 2,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let sh_a = operation_sighash(&op_a).expect("sighash");
        let sh_b = operation_sighash(&op_b).expect("sighash");
        assert_ne!(sh_a, sh_b, "different nonces → different sighashes");
    }

    /// Two operations differing only in `expiry` produce distinct sighashes — protocol-level
    /// expiry is part of the preimage, so an op signed with one expiry can't be replayed with
    /// another.
    #[test]
    fn distinct_expiries_produce_distinct_sighashes() {
        let common = (dummy_deposit_id(), [0xab; 32], 50_000u64);
        let op_a = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: common.2,
            payment_id: common.1,
            sequence_number: 1,
            nonce: 1,
            expiry: 1_000_000,
            witness: DescriptorWitness::new(),
        };
        let op_b = LedgerOperation::InvoiceLock {
            deposit_id: common.0,
            amount: common.2,
            payment_id: common.1,
            sequence_number: 1,
            nonce: 1,
            expiry: 2_000_000,
            witness: DescriptorWitness::new(),
        };
        let sh_a = operation_sighash(&op_a).expect("sighash");
        let sh_b = operation_sighash(&op_b).expect("sighash");
        assert_ne!(sh_a, sh_b, "different expiries → different sighashes");
    }
}
