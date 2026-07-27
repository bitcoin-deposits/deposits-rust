// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! [`Dep16Authorizer`] — the real `Authorizer` impl for the deposits protocol.
//!
//! Wires the dep-16 evaluator into [`deposits_protocol::Authorizer`]: takes a descriptor
//! string + a [`LedgerOperation`], parses the descriptor as dep-16 source, translates the
//! operation via [`super::operations::to_dep16`], converts the byte-stack witness into the
//! dep-16 keyed `Witness` shape (by trying each stack signature against each key the
//! descriptor mentions), and evaluates. Currently used by `DepositKeyRotate`'s conformance
//! check — later phases extend it to the lock-side
//! variants and remove the old `WitnessVerifier` path.
//!
//! v1 scope: the descriptor's keys are read as 33-byte compressed secp256k1 pubkeys
//! (bitcoin::PublicKey). x-only (BIP-340) and tr key-path support land in a later phase
//! when the descriptor catalogue introduces tr deposits.

use bitcoin::PublicKey;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::DescriptorWitness;
use deposits_protocol::Authorizer;

use super::{
    operations, EcdsaVerifier, Obligation, Verifier as Dep16Verifier, Witness as Dep16Witness,
};
use miniscript::calculus::ast::BTerm;
use miniscript::calculus::Signature as Dep16Signature;

/// dep-16-backed `Authorizer`. Holds a single ECDSA verifier; produces verdicts by
/// evaluating the calculus on the operation's translated form.
pub struct Dep16Authorizer {
    verifier: EcdsaVerifier,
}

impl Default for Dep16Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Dep16Authorizer {
    pub fn new() -> Self {
        Self {
            verifier: EcdsaVerifier::new(),
        }
    }
}

impl Authorizer for Dep16Authorizer {
    fn authorize(&self, descriptor: &str, operation: &LedgerOperation) -> bool {
        authorize_inner(&self.verifier, descriptor, operation).unwrap_or(false)
    }

    fn validate_descriptor(&self, descriptor: &str) -> Option<String> {
        match miniscript::calculus::parse::<PublicKey>(descriptor) {
            Ok(_) => None,
            Err(e) => Some(format!("{}", e)),
        }
    }
}

/// Inbound receive authorization wire format. The wallet signs the dep-17 preimage of
/// [`super::operations::receive_op`] with the same `(deposit_id, nonce, expiry, transfer_id)`
/// the node will use, and sends this struct as the `receive_witness` / `receive_signature`
/// request param.
///
/// `signatures` is a map of compressed-pubkey hex → 64-byte ECDSA signature hex. Multi-key
/// descriptors (`pk_threshold`, `pk_any`) collect one entry per signer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceiveWitness {
    /// Per-deposit monotonic nonce. Bound into the operation preimage; future per-deposit
    /// replay protection (phase 3) will reject `nonce <= last_seen`.
    pub nonce: u64,
    /// Absolute block height after which this signature is no longer accepted.
    pub expiry: u32,
    /// `compressed-pubkey-hex → 64-byte ECDSA sig hex`.
    pub signatures: std::collections::BTreeMap<String, String>,
}

impl Dep16Authorizer {
    /// Authorize an inbound receive against a deposit's descriptor. Builds the synthetic
    /// receive op (via [`super::operations::receive_op`]) with the same inputs the wallet
    /// signed against, converts the wire signatures into the dep-16 keyed witness shape, and
    /// evaluates the descriptor under `op_type = receive`.
    ///
    /// Replaces the legacy `verify_witness(descriptor, &DescriptorWitness, &message)` path
    /// for receive-side authorization. Two call sites:
    /// - admission-time receive on a `receive_requires_sig` deposit (invoice / offer creation)
    ///   — pass `transfer_id = None`
    /// - destination-side receive on a transfer release — pass `transfer_id = Some(...)`
    pub fn authorize_receive(
        &self,
        descriptor: &str,
        deposit_id: &deposits_protocol::types::DepositId,
        transfer_id: Option<&[u8]>,
        receive_witness: &ReceiveWitness,
    ) -> bool {
        authorize_receive_inner(
            &self.verifier,
            descriptor,
            deposit_id,
            transfer_id,
            receive_witness,
        )
        .unwrap_or(false)
    }
}

fn authorize_receive_inner(
    verifier: &EcdsaVerifier,
    descriptor: &str,
    deposit_id: &deposits_protocol::types::DepositId,
    transfer_id: Option<&[u8]>,
    receive_witness: &ReceiveWitness,
) -> Option<bool> {
    let d = miniscript::calculus::parse::<PublicKey>(descriptor).ok()?;
    let op = super::operations::receive_op(
        deposit_id,
        receive_witness.nonce,
        receive_witness.expiry,
        transfer_id,
    );
    let mut witness = Dep16Witness::<PublicKey>::empty();
    for (key_hex, sig_hex) in &receive_witness.signatures {
        let key_bytes = hex::decode(key_hex).ok()?;
        if key_bytes.len() != 33 {
            return None;
        }
        let key = PublicKey::from_slice(&key_bytes).ok()?;
        let sig_bytes = hex::decode(sig_hex).ok()?;
        if sig_bytes.len() != 64 {
            return None;
        }
        witness = witness.with_signature(key, Dep16Signature(sig_bytes));
    }
    let state = super::ProtocolLedgerState::empty();
    miniscript::calculus::evaluate(&d, &op, &state, &witness, verifier).ok()
}

/// The actual authorization logic, factored out so the trait method can `unwrap_or(false)`
/// on any error (parse failure, missing witness, ledger-state read on an op that doesn't
/// have one). Phase 4 keeps the "unauthorized on any error" stance from the legacy
/// `verify_witness` path; phase 5 may surface specific errors as conformance violations.
fn authorize_inner(
    verifier: &EcdsaVerifier,
    descriptor: &str,
    operation: &LedgerOperation,
) -> Option<bool> {
    // 1. Parse descriptor as dep-16 source.
    let d = miniscript::calculus::parse::<PublicKey>(descriptor).ok()?;

    // 2. Translate the protocol op into the dep-16 Operation form. None for variants
    //    that don't go through descriptor evaluation (fulfill, administrative ops).
    let dep16_op = operations::to_dep16(operation)?;

    // 3. The signing preimage the witness signatures must verify against.
    let preimage = miniscript::calculus::operation_preimage(&dep16_op);

    // 4. Convert the byte-stack witness to the dep-16 keyed shape. Walks the descriptor
    //    for pk(K) leaves; for each (signature, key) pair, tests verification; binds
    //    matches into the dep-16 witness.
    let byte_witness = extract_witness(operation)?;
    let dep16_witness = stack_to_keyed(verifier, &d, &byte_witness.stack, &preimage);

    // 5. Evaluate. ProtocolLedgerState::empty() is fine for now: DepositKeyRotate
    //    (the only variant currently routed here) doesn't read ledger state. Phase 5
    //    will plumb a real adapter when the spend-side variants start needing it.
    let state = super::ProtocolLedgerState::empty();
    miniscript::calculus::evaluate(&d, &dep16_op, &state, &dep16_witness, verifier).ok()
}

/// Pull the `witness` (or `script_witness`) field out of a `LedgerOperation` variant.
/// Returns `None` for variants that don't carry a witness or aren't routed through the
/// dep-16 path.
fn extract_witness(op: &LedgerOperation) -> Option<&DescriptorWitness> {
    match op {
        LedgerOperation::InvoiceLock { witness, .. } => Some(witness),
        LedgerOperation::OnchainLock { witness, .. } => Some(witness),
        LedgerOperation::TransferLock { witness, .. } => Some(witness),
        LedgerOperation::DepositKeyRotate { witness, .. } => Some(witness),
        // TransferComplete's script_witness is the lock's release-descriptor witness;
        // the caller routes this through Authorizer against the lock's completion_script.
        LedgerOperation::TransferComplete { script_witness, .. } => Some(script_witness),
        _ => None,
    }
}

/// Convert a positional byte-stack witness (the legacy `DescriptorWitness` shape) into
/// the dep-16 keyed `Witness`. Three parallel walks over the descriptor's body collect
/// the obligation targets, then each stack entry is tried against each unbound target:
///
/// - **Signatures** (`pk` / `pk_any` / `pk_threshold`): 64-byte entries, bound to a key
///   when ECDSA verification against the operation preimage succeeds.
/// - **Preimages** (`hashlock(H)`): any-length entries, bound to `H` when hashing the
///   entry with `H`'s hash function reproduces `H`. This is what makes HTLC
///   `TransferComplete` (courier hops, the Lightning bridge) actually *evaluate* —
///   before this walk existed, every hashlock obligation was unsatisfiable through
///   the byte-stack path and lock completion went cryptographically unenforced.
/// - **Scalars** (`pointlock(P)`): 32-byte entries, bound to `P` when the verifier
///   confirms `G·s == P` (the PTLC analog; same enforcement story).
///
/// An entry that matches multiple targets (theoretically impossible for signatures,
/// merely improbable for hashes) is bound to whichever target the walk met first —
/// the evaluator only needs *some* satisfying entry per obligation, so duplicate
/// bindings can't change a verdict.
fn stack_to_keyed(
    verifier: &EcdsaVerifier,
    descriptor: &miniscript::calculus::Descriptor<PublicKey>,
    stack: &[Vec<u8>],
    preimage: &[u8],
) -> Dep16Witness<PublicKey> {
    use miniscript::calculus::HashValue;

    let mut witness = Dep16Witness::empty();
    let body = match descriptor.body() {
        Some(b) => b,
        None => return witness, // tr(K) with no body
    };
    let keys = collect_pk_keys(body);
    let hash_targets = collect_hashlock_targets(body);
    let point_targets = collect_pointlock_targets(body);

    /// Hash `bytes` with the function `target` is tagged with and compare.
    fn preimage_matches(target: &HashValue, bytes: &[u8]) -> bool {
        use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
        match target {
            HashValue::Sha256(h) => sha256::Hash::hash(bytes).to_byte_array() == *h,
            HashValue::Hash256(h) => sha256d::Hash::hash(bytes).to_byte_array() == *h,
            HashValue::Ripemd160(h) => ripemd160::Hash::hash(bytes).to_byte_array() == *h,
            HashValue::Hash160(h) => hash160::Hash::hash(bytes).to_byte_array() == *h,
        }
    }

    for stack_bytes in stack {
        // Signature binding: 64-byte compact ECDSA only.
        if stack_bytes.len() == 64 {
            let sig = Dep16Signature(stack_bytes.clone());
            let mut bound = false;
            for key in &keys {
                if witness.signatures.contains_key(key) {
                    continue;
                }
                if verifier.verify_signature(key, &sig, preimage) {
                    witness = witness.with_signature(*key, sig.clone());
                    bound = true;
                    break;
                }
            }
            if bound {
                continue;
            }
            // A 64-byte entry that isn't a valid signature for any key falls
            // through to the preimage walk — hashlock preimages may legally
            // be 64 bytes.
        }

        // Preimage binding: any length.
        let mut bound = false;
        for target in &hash_targets {
            if witness.preimages.contains_key(target) {
                continue;
            }
            if preimage_matches(target, stack_bytes) {
                witness = witness.with_preimage(target.clone(), stack_bytes.clone());
                bound = true;
                break;
            }
        }
        if bound {
            continue;
        }

        // Scalar binding: exactly 32 bytes, and the verifier must confirm
        // the point relation (invalid scalars and non-matching points are
        // both just "no match" — the witness lacks an entry and the
        // obligation evaluates false).
        if stack_bytes.len() == 32 {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(stack_bytes);
            for point in &point_targets {
                if witness.scalars.contains_key(point) {
                    continue;
                }
                if verifier.point_is_scalar_image(point, &scalar) {
                    witness = witness.with_scalar(*point, scalar);
                    break;
                }
            }
        }
    }
    witness
}

/// Collect every literal hash referenced by a `hashlock(H)` obligation.
fn collect_hashlock_targets(t: &BTerm<PublicKey>) -> Vec<miniscript::calculus::HashValue> {
    use miniscript::calculus::ast::VTerm;
    use miniscript::calculus::Value;
    let mut out = Vec::new();
    walk_obligations(t, &mut |ob| {
        if let Obligation::Hashlock(VTerm::Lit(Value::Hash(h))) = ob {
            if !out.contains(h) {
                out.push(h.clone());
            }
        }
    });
    out
}

/// Collect every literal point referenced by a `pointlock(P)` obligation.
fn collect_pointlock_targets(t: &BTerm<PublicKey>) -> Vec<PublicKey> {
    use miniscript::calculus::ast::VTerm;
    use miniscript::calculus::Value;
    let mut out = Vec::new();
    walk_obligations(t, &mut |ob| {
        if let Obligation::Pointlock(VTerm::Lit(Value::Key(k))) = ob {
            if !out.contains(k) {
                out.push(*k);
            }
        }
    });
    out
}

/// Visit every `Prove(obligation)` leaf in a body term.
fn walk_obligations<F: FnMut(&Obligation<PublicKey>)>(t: &BTerm<PublicKey>, f: &mut F) {
    match t {
        BTerm::Prove(ob) => f(ob),
        BTerm::And(bs) | BTerm::Or(bs) | BTerm::Thresh(_, bs) => {
            for b in bs {
                walk_obligations(b, f);
            }
        }
        BTerm::Not(b) => walk_obligations(b, f),
        BTerm::If(c, t2, e) => {
            walk_obligations(c, f);
            walk_obligations(t2, f);
            walk_obligations(e, f);
        }
        BTerm::Match { arms, default, .. } => {
            for (_, body) in arms {
                walk_obligations(body, f);
            }
            walk_obligations(default, f);
        }
        BTerm::Const(_) | BTerm::Cmp(..) | BTerm::State(..) => {}
    }
}

/// Recursively walk a body term and collect every key referenced by a signature-bearing
/// obligation (`pk(K)`, `pk_any([K, ...])`, `pk_threshold(k, [K, ...])`). The collected
/// keys are the universe of candidates for signature binding; `hashlock` and
/// `pointlock` targets have their own collectors above. `pk_h` and `attest` remain
/// unfed by the byte-stack path (key-hash reveals and attestations need richer wire
/// shapes than bare stack entries) — they'll grow dedicated request fields when a
/// lock-side descriptor first uses them.
fn collect_pk_keys(t: &BTerm<PublicKey>) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    collect_pk_keys_into(t, &mut keys);
    keys
}

fn collect_pk_keys_into(t: &BTerm<PublicKey>, out: &mut Vec<PublicKey>) {
    use miniscript::calculus::ast::VTerm;
    use miniscript::calculus::Value;
    // Helper: pull a single literal key out of a VTerm if it is one.
    fn lit_key(v: &VTerm<PublicKey>) -> Option<PublicKey> {
        match v {
            VTerm::Lit(Value::Key(k)) => Some(*k),
            _ => None,
        }
    }
    // Helper: pull a literal list of keys out of a VTerm if it is one.
    fn lit_key_list(v: &VTerm<PublicKey>) -> Vec<PublicKey> {
        match v {
            VTerm::Lit(Value::List(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::Key(k) => Some(*k),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
    fn push_unique(out: &mut Vec<PublicKey>, k: PublicKey) {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    match t {
        BTerm::Prove(Obligation::Pk(v)) => {
            if let Some(k) = lit_key(v) {
                push_unique(out, k);
            }
        }
        BTerm::Prove(Obligation::PkAny(v)) | BTerm::Prove(Obligation::Multi(_, v)) => {
            for k in lit_key_list(v) {
                push_unique(out, k);
            }
        }
        BTerm::Prove(_) => {} // pk_h / hashlock / attest — see fn doc.
        BTerm::And(bs) | BTerm::Or(bs) | BTerm::Thresh(_, bs) => {
            for b in bs {
                collect_pk_keys_into(b, out);
            }
        }
        BTerm::Not(b) => collect_pk_keys_into(b, out),
        BTerm::If(c, t, e) => {
            collect_pk_keys_into(c, out);
            collect_pk_keys_into(t, out);
            collect_pk_keys_into(e, out);
        }
        BTerm::Match { arms, default, .. } => {
            for (_, body) in arms {
                collect_pk_keys_into(body, out);
            }
            collect_pk_keys_into(default, out);
        }
        BTerm::Const(_) | BTerm::Cmp(..) | BTerm::State(..) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use deposits_protocol::types::DescriptorWitness;

    fn keypair(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        (sk, pk)
    }

    fn dummy_deposit_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xde;
        id[1] = 0xad;
        id
    }

    /// A real keypair signs a DepositKeyRotate against a wsh(pk(K)) deposit; the
    /// Dep16Authorizer accepts. Exercises: descriptor parse, operation translation,
    /// preimage construction, key-collection walk, witness conversion, evaluation.
    #[test]
    fn authorizes_deposit_key_rotate_when_owner_signs() {
        let (sk, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(), // filled below
        };

        // Sign the operation preimage with the deposit's owner key.
        let dep16_op = operations::to_dep16(&op).unwrap();
        let preimage = miniscript::calculus::operation_preimage(&dep16_op);
        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&sk, &preimage);

        // Re-build the op with the signature in its witness stack.
        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness { stack: vec![sig.0] },
        };

        assert!(
            auth.authorize(&descriptor, &op_signed),
            "owner-signed rotation must be authorized"
        );
    }

    /// A signature by a different key does not authorize. Confirms the Dep16Authorizer
    /// actually verifies signatures rather than accepting blindly.
    #[test]
    fn rejects_deposit_key_rotate_signed_by_wrong_key() {
        let (_, owner_pk) = keypair(0x11);
        let (impostor_sk, _) = keypair(0x99);
        let descriptor = format!("wsh(prove(pk({})))", owner_pk);
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let dep16_op = operations::to_dep16(&op).unwrap();
        let preimage = miniscript::calculus::operation_preimage(&dep16_op);
        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&impostor_sk, &preimage);

        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness { stack: vec![sig.0] },
        };
        assert!(
            !auth.authorize(&descriptor, &op_signed),
            "impostor-signed rotation must be rejected",
        );
    }

    /// A signature over a *different* operation does not authorize this one. The
    /// dep-17 operation preimage embeds nonce, expiry, deposit_id, op_type and args;
    /// a signature over op_a's preimage cannot replay against op_b. This is the
    /// concrete replay-protection property dep-17 was designed for.
    #[test]
    fn signature_over_different_operation_is_rejected() {
        let (sk, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        // Sign op_a's preimage.
        let op_a = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: "wsh(prove(pk(_a)))".to_string(),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let preimage_a =
            miniscript::calculus::operation_preimage(&operations::to_dep16(&op_a).unwrap());
        let verifier = EcdsaVerifier::new();
        let sig_a = verifier.sign(&sk, &preimage_a);

        // Attach sig_a to op_b (different new_descriptor — different preimage).
        let op_b = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: "wsh(prove(pk(_b)))".to_string(),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig_a.0],
            },
        };
        assert!(
            !auth.authorize(&descriptor, &op_b),
            "signature over a different op must not authorize this one",
        );
    }

    /// A 2-of-3 multisig descriptor authorizes when any two of three sign. The
    /// stack_to_keyed helper has to bind two distinct signatures to two of the
    /// three keys; the dep-16 evaluator's pk_threshold sees two valid sigs and
    /// the threshold is met.
    #[test]
    fn authorizes_threshold_with_two_of_three() {
        let (sk_a, pk_a) = keypair(0x01);
        let (sk_b, pk_b) = keypair(0x02);
        let (_, pk_c) = keypair(0x03);
        let descriptor = format!(
            "wsh(prove(pk_threshold(2, [{}, {}, {}])))",
            pk_a, pk_b, pk_c
        );
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let preimage =
            miniscript::calculus::operation_preimage(&operations::to_dep16(&op).unwrap());
        let verifier = EcdsaVerifier::new();
        let sig_a = verifier.sign(&sk_a, &preimage);
        let sig_b = verifier.sign(&sk_b, &preimage);

        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig_a.0, sig_b.0],
            },
        };
        assert!(
            auth.authorize(&descriptor, &op_signed),
            "2-of-3 with two sigs must satisfy the threshold",
        );

        // Same descriptor, only one signature → under-threshold, rejected.
        let only_a = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![verifier.sign(&sk_a, &preimage).0],
            },
        };
        assert!(
            !auth.authorize(&descriptor, &only_a),
            "2-of-3 with one sig must NOT satisfy the threshold",
        );
    }

    /// validate_descriptor rejects unparseable strings, accepts parseable ones.
    #[test]
    fn validate_descriptor_round_trips() {
        let auth = Dep16Authorizer::new();
        let (_, pk) = keypair(0x11);
        let valid = format!("wsh(prove(pk({})))", pk);
        assert!(auth.validate_descriptor(&valid).is_none());
        assert!(auth.validate_descriptor("not a descriptor").is_some());
    }

    /// Operations that don't go through descriptor evaluation (fulfills,
    /// administrative ops) return false — the Authorizer has nothing to evaluate
    /// against. The caller decides what that means (typically: don't run the check
    /// for these variants at all).
    #[test]
    fn unevaluable_operations_return_false() {
        let (_, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        let fulfill = LedgerOperation::InvoiceFulfill {
            deposit_id: dummy_deposit_id(),
            amount: 50,
            payment_id: [0xab; 32],
            sequence_number: 1,
            preimage: [0xee; 32],
            witness: DescriptorWitness::new(),
            commitment: None,
        };
        assert!(!auth.authorize(&descriptor, &fulfill));

        let close = LedgerOperation::DepositClose {
            deposit_id: dummy_deposit_id(),
            commitment: None,
        };
        assert!(!auth.authorize(&descriptor, &close));
    }

    /// HTLC release: a `TransferComplete` whose script_witness reveals the
    /// correct preimage satisfies the lock's `sha256(H)` completion_script.
    /// This is the enforcement the bridge and courier flows rest on — before
    /// the preimage walk in `stack_to_keyed`, this authorize() returned
    /// false for EVERY hashlock witness, correct or not.
    #[test]
    fn authorizes_hashlock_release_with_correct_preimage() {
        use bitcoin::hashes::{sha256, Hash};
        let preimage_bytes = [0xab; 32];
        let hash = sha256::Hash::hash(&preimage_bytes).to_byte_array();
        let completion_script = format!("sha256({})", hex::encode(hash));
        let auth = Dep16Authorizer::new();

        let good = LedgerOperation::TransferComplete {
            transfer_id: [0x77; 32],
            script_witness: DescriptorWitness {
                stack: vec![preimage_bytes.to_vec()],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            auth.authorize(&completion_script, &good),
            "correct preimage must satisfy sha256 lock"
        );

        let bad = LedgerOperation::TransferComplete {
            transfer_id: [0x77; 32],
            script_witness: DescriptorWitness {
                stack: vec![vec![0xcd; 32]],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            !auth.authorize(&completion_script, &bad),
            "wrong preimage must NOT satisfy sha256 lock"
        );

        let empty = LedgerOperation::TransferComplete {
            transfer_id: [0x77; 32],
            script_witness: DescriptorWitness::new(),
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            !auth.authorize(&completion_script, &empty),
            "empty witness must NOT satisfy sha256 lock"
        );
    }

    /// PTLC release: a `TransferComplete` revealing the scalar `s` whose
    /// curve image is `P` satisfies `pointlock(P)`; a scalar for a different
    /// point does not. Mirrors the hashlock test for the PTLC path.
    #[test]
    fn authorizes_pointlock_release_with_correct_scalar() {
        let (sk, pk) = keypair(0x42);
        let completion_script = format!("pointlock({})", pk);
        let auth = Dep16Authorizer::new();

        let good = LedgerOperation::TransferComplete {
            transfer_id: [0x88; 32],
            script_witness: DescriptorWitness {
                stack: vec![sk.secret_bytes().to_vec()],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            auth.authorize(&completion_script, &good),
            "matching scalar must satisfy pointlock"
        );

        let (other_sk, _) = keypair(0x43);
        let bad = LedgerOperation::TransferComplete {
            transfer_id: [0x88; 32],
            script_witness: DescriptorWitness {
                stack: vec![other_sk.secret_bytes().to_vec()],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            !auth.authorize(&completion_script, &bad),
            "scalar for a different point must NOT satisfy pointlock"
        );
    }

    /// Combined lock: `sha256(H) and pk(K)` needs BOTH the preimage and the
    /// signature in one stack — exercises signature + preimage binding from
    /// a single walk, including the 64-byte-entry fall-through (a 64-byte
    /// hashlock preimage must not be swallowed by the signature path).
    #[test]
    fn authorizes_combined_hashlock_and_pk() {
        use bitcoin::hashes::{sha256, Hash};
        let (sk, pk) = keypair(0x55);
        // 64-byte preimage on purpose: lands in the signature-size branch
        // first, fails sig verification, falls through to preimage binding.
        let preimage_bytes = [0x5a; 64];
        let hash = sha256::Hash::hash(&preimage_bytes).to_byte_array();
        let script = format!("and(sha256({}), pk({}))", hex::encode(hash), pk);
        let auth = Dep16Authorizer::new();

        let op_unsigned = LedgerOperation::TransferComplete {
            transfer_id: [0x99; 32],
            script_witness: DescriptorWitness::new(),
            commitment: None,
            dest_commitment: None,
        };
        let msg =
            miniscript::calculus::operation_preimage(&operations::to_dep16(&op_unsigned).unwrap());
        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&sk, &msg);

        let both = LedgerOperation::TransferComplete {
            transfer_id: [0x99; 32],
            script_witness: DescriptorWitness {
                stack: vec![preimage_bytes.to_vec(), sig.0.clone()],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            auth.authorize(&script, &both),
            "preimage + signature must satisfy the combined lock"
        );

        let only_preimage = LedgerOperation::TransferComplete {
            transfer_id: [0x99; 32],
            script_witness: DescriptorWitness {
                stack: vec![preimage_bytes.to_vec()],
            },
            commitment: None,
            dest_commitment: None,
        };
        assert!(
            !auth.authorize(&script, &only_preimage),
            "preimage alone must NOT satisfy and(hashlock, pk)"
        );
    }
}
