//! Miniscript descriptor verification for deposits.
//!
//! All deposit operations are authorized by satisfying a miniscript descriptor.
//! The `pk()` case is optimized as a fast path (direct Schnorr verification),
//! but any valid miniscript descriptor is supported.

use crate::types::DescriptorWitness;
use crate::DepositsError;
use bitcoin::secp256k1::{Message, Secp256k1};

/// Verify that a witness satisfies a descriptor for a given message hash.
///
/// This is the single entry point for all deposit authorization checks.
/// Transfers, withdrawals, invoice requests, and receive authorizations
/// all go through this function.
///
/// # Fast path
/// For `pk(<compressed_pubkey_hex>)` descriptors, performs direct Schnorr
/// signature verification without invoking the miniscript library.
///
/// # General path
/// For other descriptors, parses as miniscript and evaluates the witness
/// stack against it.
pub fn verify_witness(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
    chain_tip: u32,
) -> Result<bool, DepositsError> {
    // Fast path: pk() descriptor — direct Schnorr verification. No
    // timelock context applies to a single-key descriptor, so chain_tip
    // is ignored here.
    if let Some(result) = try_verify_pk(descriptor, witness, message_hash)? {
        return Ok(result);
    }

    // General path: parse as miniscript; chain_tip threads through to
    // policy evaluation for `After(n)` checks.
    verify_miniscript(descriptor, witness, message_hash, chain_tip)
}

/// Extract the pubkey from a `pk()` descriptor and verify a Schnorr signature.
/// Returns `Ok(None)` if the descriptor is not a `pk()` descriptor.
fn try_verify_pk(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
) -> Result<Option<bool>, DepositsError> {
    if !(descriptor.starts_with("pk(") && descriptor.ends_with(")")) {
        return Ok(None);
    }

    let pk_hex = &descriptor[3..descriptor.len() - 1];
    let pubkey_bytes = hex::decode(pk_hex).map_err(|_| DepositsError::ProtocolViolation {
        violation_type: "invalid_descriptor".to_string(),
        details: "Invalid pubkey hex in pk() descriptor".to_string(),
    })?;

    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_descriptor".to_string(),
            details: "Invalid pubkey in pk() descriptor".to_string(),
        }
    })?;

    // Need exactly one 64-byte signature
    if witness.stack.len() != 1 || witness.stack[0].len() != 64 {
        return Ok(Some(false));
    }

    use bitcoin::secp256k1::schnorr::Signature;
    let sig = match Signature::from_slice(&witness.stack[0]) {
        Ok(s) => s,
        Err(_) => return Ok(Some(false)),
    };

    let secp = Secp256k1::verification_only();
    let x_only = pubkey.x_only_public_key().0;
    let msg = Message::from_digest(*message_hash);

    Ok(Some(secp.verify_schnorr(&sig, &msg, &x_only).is_ok()))
}

/// Verify a witness against a general miniscript descriptor.
///
/// The descriptor is parsed, lifted to its abstract `Semantic` policy,
/// and then evaluated against a "did this key sign the message?"
/// predicate. Going through the policy AST (rather than string-matching
/// the descriptor) means every combinator the miniscript parser
/// accepts — `and`, `or`, `thresh`, nested forms — is honored
/// structurally, with no per-shape special cases.
///
/// Time/hashlocks present in the descriptor are evaluated as
/// `false`: our message-signing model has no witness slot for
/// preimages or sequence/locktime proofs, so any subterm gated on
/// them is unsatisfiable here. A descriptor like
/// `or(pk(A), and(pk(B), older(144)))` therefore reduces to "A
/// must sign" — exactly what we want for off-chain authorization.
fn verify_miniscript(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
    chain_tip: u32,
) -> Result<bool, DepositsError> {
    use miniscript::policy::Liftable;
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    // Deposits use raw key hex; wrap in wsh() if no top-level
    // context is present so miniscript will parse it.
    let desc_str = if descriptor.starts_with("wsh(")
        || descriptor.starts_with("sh(")
        || descriptor.starts_with("tr(")
    {
        descriptor.to_string()
    } else {
        format!("wsh({})", descriptor)
    };

    let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).map_err(|e| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_descriptor".to_string(),
            details: format!("Failed to parse descriptor '{}': {}", descriptor, e),
        }
    })?;

    let policy = desc.lift().map_err(|e| DepositsError::ProtocolViolation {
        violation_type: "invalid_descriptor".to_string(),
        details: format!("Descriptor '{}' does not lift to a policy: {}", descriptor, e),
    })?;

    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(*message_hash);

    let key_signed = |pk: &DescriptorPublicKey| -> bool {
        let xonly = match pk {
            DescriptorPublicKey::Single(single) => match &single.key {
                miniscript::descriptor::SinglePubKey::FullKey(p) => p.inner.x_only_public_key().0,
                miniscript::descriptor::SinglePubKey::XOnly(x) => *x,
            },
            // XPub variants aren't used in deposits descriptors — they'd
            // require derivation paths that we don't carry here.
            _ => return false,
        };
        witness.stack.iter().any(|sig_bytes| {
            if sig_bytes.len() != 64 {
                return false;
            }
            bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map(|sig| secp.verify_schnorr(&sig, &msg, &xonly).is_ok())
                .unwrap_or(false)
        })
    };

    Ok(evaluate_policy(&policy, &key_signed, chain_tip))
}

/// Recursively evaluate a lifted `Semantic` policy with a "is this key
/// satisfied?" predicate. The predicate decides only at `Key(_)`
/// leaves; combinators and threshold structure come straight from the
/// policy AST so `and`/`or`/`thresh` compose correctly.
///
/// `chain_tip` is the daemon's view of the latest Bitcoin block height,
/// used to evaluate `After(N)` block-height locks. We subtract
/// `DESCRIPTOR_TIMELOCK_CONFIRMATIONS` before comparing to keep
/// authorizations stable across short reorgs (see the constant's docs).
fn evaluate_policy<F>(
    p: &miniscript::policy::Semantic<miniscript::DescriptorPublicKey>,
    signed: &F,
    chain_tip: u32,
) -> bool
where
    F: Fn(&miniscript::DescriptorPublicKey) -> bool,
{
    use miniscript::policy::Semantic::*;
    match p {
        Trivial => true,
        Unsatisfiable => false,
        Key(pk) => signed(pk),
        Thresh(t) => t
            .iter()
            .filter(|sub| evaluate_policy(sub, signed, chain_tip))
            .count()
            >= t.k(),
        After(n) => {
            // BIP-65: locktime values <500_000_000 are block heights;
            // higher values are Unix timestamps. We support only the
            // block-height flavor here — wall-clock evaluation would
            // need a separate, equally-conservative time source.
            let n = n.to_consensus_u32();
            if n >= 500_000_000 {
                return false;
            }
            let effective = chain_tip
                .saturating_sub(deposits_protocol::constants::DESCRIPTOR_TIMELOCK_CONFIRMATIONS);
            effective >= n
        }
        // `Older(_)` is relative; off-chain there's no canonical baseline
        // (on-chain it's "input maturity"). Until we pin a referent for
        // it, treat it as unsatisfiable so authorizations stay strict.
        // Hash-preimage gates have no witness slot in our signing model
        // and are likewise unsatisfiable.
        Older(_) | Sha256(_) | Hash256(_) | Ripemd160(_) | Hash160(_) => false,
    }
}

/// Witness verifier implementation using real cryptographic verification.
///
/// This implements the `WitnessVerifier` trait from deposits-protocol,
/// providing descriptor-based witness verification (Schnorr/miniscript)
/// and ECDSA/Schnorr signature verification.
///
/// `chain_tip` is the operator's view of the Bitcoin chain tip at the
/// moment this verifier is constructed; descriptor `after(N)` checks
/// compare against `chain_tip - DESCRIPTOR_TIMELOCK_CONFIRMATIONS`. A
/// freshly constructed verifier with `chain_tip = 0` will treat every
/// timelock as unsatisfiable, which is the safe default for code paths
/// that haven't yet plumbed a real height through.
pub struct CoreWitnessVerifier {
    pub chain_tip: u32,
}

impl CoreWitnessVerifier {
    pub fn new(chain_tip: u32) -> Self {
        Self { chain_tip }
    }
}

impl deposits_protocol::WitnessVerifier for CoreWitnessVerifier {
    fn verify_witness(
        &self,
        descriptor: &str,
        witness: &DescriptorWitness,
        message_hash: &[u8; 32],
    ) -> bool {
        verify_witness(descriptor, witness, message_hash, self.chain_tip).unwrap_or(false)
    }

    fn validate_descriptor(&self, descriptor: &str) -> Option<String> {
        use miniscript::{Descriptor, DescriptorPublicKey};
        use std::str::FromStr;

        // pk(<hex>) — fast path matches verify_witness's try_verify_pk.
        if descriptor.starts_with("pk(") && descriptor.ends_with(')') {
            let pk_hex = &descriptor[3..descriptor.len() - 1];
            return match bitcoin::secp256k1::PublicKey::from_slice(
                &hex::decode(pk_hex).ok()?,
            ) {
                Ok(_) => None,
                Err(e) => Some(format!("invalid pubkey in pk(): {}", e)),
            };
        }

        // Bare-policy descriptors get wsh-wrapped to match the parsing
        // path verify_miniscript uses; otherwise miniscript refuses
        // raw-key forms.
        let desc_str = if descriptor.starts_with("wsh(")
            || descriptor.starts_with("sh(")
            || descriptor.starts_with("tr(")
        {
            descriptor.to_string()
        } else {
            format!("wsh({})", descriptor)
        };
        match Descriptor::<DescriptorPublicKey>::from_str(&desc_str) {
            Ok(_) => None,
            Err(e) => Some(e.to_string()),
        }
    }

    fn verify_signature(
        &self,
        pubkey: &bitcoin::secp256k1::PublicKey,
        message: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(*message);

        // Try Schnorr first (64-byte signatures)
        if let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(signature) {
            let x_only = pubkey.x_only_public_key().0;
            if secp.verify_schnorr(&sig, &msg, &x_only).is_ok() {
                return true;
            }
        }

        // Try ECDSA (DER-encoded inside 64 bytes — compact format)
        if let Ok(sig) = bitcoin::secp256k1::ecdsa::Signature::from_compact(signature) {
            if secp.verify_ecdsa(&msg, &sig, pubkey).is_ok() {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn make_keypair() -> (SecretKey, bitcoin::secp256k1::PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    fn sign_message(sk: &SecretKey, msg_hash: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, sk);
        let msg = Message::from_digest(*msg_hash);
        secp.sign_schnorr_no_aux_rand(&msg, &keypair).serialize()
    }

    #[test]
    fn pk_descriptor_valid_signature() {
        let (sk, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let sig = sign_message(&sk, &msg_hash);
        let witness = DescriptorWitness {
            stack: vec![sig.to_vec()],
        };

        assert!(verify_witness(&descriptor, &witness, &msg_hash, 0).unwrap());
    }

    #[test]
    fn pk_descriptor_invalid_signature() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash, 0).unwrap());
    }

    #[test]
    fn pk_descriptor_wrong_message() {
        let (sk, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let wrong_hash = [0xBB; 32];
        let sig = sign_message(&sk, &msg_hash);
        let witness = DescriptorWitness {
            stack: vec![sig.to_vec()],
        };

        assert!(!verify_witness(&descriptor, &witness, &wrong_hash, 0).unwrap());
    }

    #[test]
    fn pk_descriptor_empty_witness() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness { stack: vec![] };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash, 0).unwrap());
    }

    #[test]
    fn invalid_descriptor_rejected() {
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        let result = verify_witness("not_a_descriptor", &witness, &msg_hash, 0);
        assert!(result.is_err());
    }

    /// Build a fresh keypair from a 32-byte seed slice. Used to drive
    /// the multi-key descriptor tests with three independent keys.
    fn keypair_from_seed(seed: u8) -> (SecretKey, bitcoin::secp256k1::PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    /// Multi-key descriptor regression: a 2-of-3 multisig over Schnorr
    /// keys is satisfied by *any* two valid signatures (in any order).
    /// This is the principal regression target for Phase-4 — it would
    /// have failed under the old `pk()`-only assumption baked into the
    /// daemon's wire-protocol surface.
    #[test]
    fn multi_2_of_3_satisfies_with_two_sigs() {
        let (sk_a, pk_a) = keypair_from_seed(1);
        let (sk_b, pk_b) = keypair_from_seed(2);
        let (_, pk_c) = keypair_from_seed(3);

        // Use raw compressed-hex form — matches the wallet's descriptor shape.
        let descriptor = format!(
            "multi(2,{},{},{})",
            hex::encode(pk_a.serialize()),
            hex::encode(pk_b.serialize()),
            hex::encode(pk_c.serialize())
        );
        let msg_hash = [0xCD; 32];

        // A + B sign — should satisfy.
        let witness_ab = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec(), sign_message(&sk_b, &msg_hash).to_vec()],
        };
        assert!(
            verify_witness(&descriptor, &witness_ab, &msg_hash, 0).unwrap(),
            "2-of-3: A+B sigs should satisfy"
        );

        // Only A signs — under-threshold, must fail.
        let witness_a = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_a, &msg_hash, 0).unwrap(),
            "2-of-3: A alone must NOT satisfy"
        );

        // A signs twice with the same key — duplicates don't count.
        let sig_a = sign_message(&sk_a, &msg_hash);
        let witness_aa = DescriptorWitness {
            stack: vec![sig_a.to_vec(), sig_a.to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_aa, &msg_hash, 0).unwrap(),
            "2-of-3: dup A sigs must NOT satisfy threshold"
        );

        // Wrong message — sigs valid but bound to a different digest.
        let other_hash = [0xEF; 32];
        let witness_ab_wrong = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec(), sign_message(&sk_b, &msg_hash).to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_ab_wrong, &other_hash, 0).unwrap(),
            "2-of-3: sigs over wrong message must NOT satisfy"
        );
    }

    /// Disjunctions used to be silently strengthened into conjunctions:
    /// the pre-lift code counted both keys and required N-of-N, so
    /// `or_d(pk(A), pk(B))` demanded *both* signatures. Under the
    /// policy-lift evaluator, the lifted `Thresh(k=1, ...)` is honored
    /// and a single signature suffices.
    #[test]
    fn or_d_one_sig_satisfies() {
        let (sk_a, pk_a) = keypair_from_seed(1);
        let (_, pk_b) = keypair_from_seed(2);

        let descriptor = format!(
            "wsh(or_d(pk({}),pk({})))",
            hex::encode(pk_a.serialize()),
            hex::encode(pk_b.serialize())
        );
        let msg_hash = [0xCD; 32];

        let witness_a = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec()],
        };
        assert!(
            verify_witness(&descriptor, &witness_a, &msg_hash, 0).unwrap(),
            "or_d: A alone must satisfy a disjunction"
        );

        // No signatures at all — must fail.
        let witness_none = DescriptorWitness { stack: vec![] };
        assert!(
            !verify_witness(&descriptor, &witness_none, &msg_hash, 0).unwrap(),
            "or_d: empty witness must NOT satisfy"
        );
    }

    /// Hash-preimage and `older(N)` (relative-time) sub-terms have no
    /// witness slot in our off-chain signing model, so any branch
    /// gated on them is unsatisfiable. `and_v(v:pk(A), older(144))`
    /// can't be satisfied even with A's signature.
    #[test]
    fn timelock_branch_is_unsatisfiable() {
        let (sk_a, pk_a) = keypair_from_seed(1);
        let descriptor = format!(
            "wsh(and_v(v:pk({}),older(144)))",
            hex::encode(pk_a.serialize())
        );
        let msg_hash = [0xCD; 32];

        let witness_a = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_a, &msg_hash, 0).unwrap(),
            "timelock-gated branch must NOT satisfy in off-chain context"
        );
    }

    /// `after(N)` (absolute block-height lock) is satisfied iff the
    /// chain tip has buried `N` by `DESCRIPTOR_TIMELOCK_CONFIRMATIONS`
    /// blocks. Tests three points around the boundary at N=900_000:
    ///   - tip exactly `N + 5`: 5 < 6 confs, still unsatisfiable
    ///   - tip `N + 6`: hits the confirmation depth, satisfiable
    ///   - tip well past: trivially satisfiable
    /// And one without any signature (must fail regardless).
    #[test]
    fn after_block_height_uses_tip_minus_confirmations() {
        use deposits_protocol::constants::DESCRIPTOR_TIMELOCK_CONFIRMATIONS;
        assert_eq!(DESCRIPTOR_TIMELOCK_CONFIRMATIONS, 6, "test assumes 6-conf default");

        let (sk_a, pk_a) = keypair_from_seed(1);
        const LOCK: u32 = 900_000;
        let descriptor = format!(
            "wsh(and_v(v:pk({}),after({})))",
            hex::encode(pk_a.serialize()),
            LOCK,
        );
        let msg_hash = [0xCD; 32];
        let signed = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec()],
        };
        let none = DescriptorWitness { stack: vec![] };

        // tip is below lock + confs → unsatisfiable
        assert!(
            !verify_witness(&descriptor, &signed, &msg_hash, LOCK + 5).unwrap(),
            "after(N): tip - confs < N must NOT satisfy"
        );
        // tip exactly at lock + confs → satisfiable
        assert!(
            verify_witness(&descriptor, &signed, &msg_hash, LOCK + 6).unwrap(),
            "after(N): tip - confs == N must satisfy"
        );
        // tip well past → satisfiable
        assert!(
            verify_witness(&descriptor, &signed, &msg_hash, LOCK + 1000).unwrap(),
            "after(N): tip far past N must satisfy"
        );
        // signature missing → never satisfies, regardless of tip
        assert!(
            !verify_witness(&descriptor, &none, &msg_hash, LOCK + 1000).unwrap(),
            "after(N): no signature must NOT satisfy"
        );
    }
}
