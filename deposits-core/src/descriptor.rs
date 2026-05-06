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
) -> Result<bool, DepositsError> {
    // Fast path: pk() descriptor — direct Schnorr verification
    if let Some(result) = try_verify_pk(descriptor, witness, message_hash)? {
        return Ok(result);
    }

    // General path: parse as miniscript
    verify_miniscript(descriptor, witness, message_hash)
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
/// Parses the descriptor, checks each signature in the witness stack
/// against the message hash, and evaluates satisfaction. Each key may
/// only be credited once, so duplicate signatures don't cumulate
/// toward the threshold.
fn verify_miniscript(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
) -> Result<bool, DepositsError> {
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    // Try to parse as a miniscript descriptor
    // Deposits use raw key hex, so wrap in a bare wsh context for parsing
    let desc_str = if descriptor.starts_with("wsh(")
        || descriptor.starts_with("sh(")
        || descriptor.starts_with("tr(")
    {
        descriptor.to_string()
    } else {
        // Bare policy — wrap in wsh() for miniscript parsing
        format!("wsh({})", descriptor)
    };

    let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).map_err(|e| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_descriptor".to_string(),
            details: format!("Failed to parse descriptor '{}': {}", descriptor, e),
        }
    })?;

    // For each key in the descriptor, check if the witness contains a valid
    // Schnorr signature for that key over the message_hash
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(*message_hash);

    // Extract all pubkeys from the descriptor
    let mut keys = Vec::new();
    extract_keys(&desc, &mut keys);

    // For each key, count it as "satisfied" iff at least one stack entry
    // is a valid Schnorr signature by that key. Tallying per-key (rather
    // than per-stack-entry) prevents a single signature from doubling up
    // toward a threshold.
    let mut satisfied = 0usize;
    for key in &keys {
        let x_only = key.x_only_public_key().0;
        let mut hit = false;
        for sig_bytes in &witness.stack {
            if sig_bytes.len() != 64 {
                continue;
            }
            if let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes) {
                if secp.verify_schnorr(&sig, &msg, &x_only).is_ok() {
                    hit = true;
                    break;
                }
            }
        }
        if hit {
            satisfied += 1;
        }
    }

    // Determine required signatures from the descriptor structure
    let required = required_sigs(descriptor);

    Ok(satisfied >= required)
}

/// Extract all public keys from a descriptor.
fn extract_keys(
    desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    keys: &mut Vec<bitcoin::secp256k1::PublicKey>,
) {
    use miniscript::ForEachKey;
    desc.for_each_key(|key| {
        if let miniscript::DescriptorPublicKey::Single(single) = key {
            match &single.key {
                miniscript::descriptor::SinglePubKey::FullKey(pk) => {
                    keys.push(pk.inner);
                }
                miniscript::descriptor::SinglePubKey::XOnly(xonly) => {
                    // Convert x-only to compressed (assume even y)
                    let mut bytes = [0u8; 33];
                    bytes[0] = 0x02;
                    bytes[1..].copy_from_slice(&xonly.serialize());
                    if let Ok(pk) = bitcoin::secp256k1::PublicKey::from_slice(&bytes) {
                        keys.push(pk);
                    }
                }
            }
        }
        true // continue iterating
    });
}

/// Determine the minimum number of signatures required to satisfy a
/// descriptor. We special-case the most common multi-key shapes —
/// `multi(k, ...)` and `thresh(k, ...)` at the top of the descriptor
/// (optionally wrapped in `wsh(...)` / `sh(...)`) — by parsing `k`
/// directly from the descriptor string. Anything else is treated
/// conservatively as N-of-N over the keys it references, mirroring
/// the behavior before the threshold cases were special-cased.
fn required_sigs(descriptor: &str) -> usize {
    // Strip a single leading wrapper (wsh / sh / tr) so we see the
    // payload shape directly.
    let inner = strip_wrapper(descriptor.trim());
    if let Some(k) = parse_threshold_k(inner) {
        return k.max(1);
    }

    // Fallback: count distinct pubkey appearances. This is conservative
    // (treats and(A,B) as 2-of-2, and over-rejects or() variants) but
    // it preserves the pre-threshold behavior for anything we don't
    // recognize structurally.
    use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
    use std::str::FromStr;
    let desc_str = if descriptor.starts_with("wsh(")
        || descriptor.starts_with("sh(")
        || descriptor.starts_with("tr(")
    {
        descriptor.to_string()
    } else {
        format!("wsh({})", descriptor)
    };
    if let Ok(desc) = Descriptor::<DescriptorPublicKey>::from_str(&desc_str) {
        let mut count = 0usize;
        desc.for_each_key(|_| {
            count += 1;
            true
        });
        return count.max(1);
    }
    1
}

/// Peel one layer of `wsh(...)`, `sh(...)`, or `tr(...)` if present.
fn strip_wrapper(s: &str) -> &str {
    for prefix in ["wsh(", "sh(", "tr("] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if let Some(inner) = rest.strip_suffix(')') {
                return inner;
            }
        }
    }
    s
}

/// Extract `k` from `multi(k, ...)` or `thresh(k, ...)` at the start
/// of `s`. Returns `None` if `s` isn't shaped like that.
fn parse_threshold_k(s: &str) -> Option<usize> {
    for prefix in ["multi(", "thresh(", "multi_a(", "sortedmulti("] {
        if let Some(rest) = s.strip_prefix(prefix) {
            // First comma-delimited field is the threshold integer.
            let k_str = rest.split(',').next()?.trim();
            return k_str.parse::<usize>().ok();
        }
    }
    None
}

/// Witness verifier implementation using real cryptographic verification.
///
/// This implements the `WitnessVerifier` trait from deposits-protocol,
/// providing descriptor-based witness verification (Schnorr/miniscript)
/// and ECDSA/Schnorr signature verification.
pub struct CoreWitnessVerifier;

impl deposits_protocol::WitnessVerifier for CoreWitnessVerifier {
    fn verify_witness(
        &self,
        descriptor: &str,
        witness: &DescriptorWitness,
        message_hash: &[u8; 32],
    ) -> bool {
        verify_witness(descriptor, witness, message_hash).unwrap_or(false)
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

        assert!(verify_witness(&descriptor, &witness, &msg_hash).unwrap());
    }

    #[test]
    fn pk_descriptor_invalid_signature() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash).unwrap());
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

        assert!(!verify_witness(&descriptor, &witness, &wrong_hash).unwrap());
    }

    #[test]
    fn pk_descriptor_empty_witness() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness { stack: vec![] };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash).unwrap());
    }

    #[test]
    fn invalid_descriptor_rejected() {
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        let result = verify_witness("not_a_descriptor", &witness, &msg_hash);
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
            verify_witness(&descriptor, &witness_ab, &msg_hash).unwrap(),
            "2-of-3: A+B sigs should satisfy"
        );

        // Only A signs — under-threshold, must fail.
        let witness_a = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_a, &msg_hash).unwrap(),
            "2-of-3: A alone must NOT satisfy"
        );

        // A signs twice with the same key — duplicates don't count.
        let sig_a = sign_message(&sk_a, &msg_hash);
        let witness_aa = DescriptorWitness {
            stack: vec![sig_a.to_vec(), sig_a.to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_aa, &msg_hash).unwrap(),
            "2-of-3: dup A sigs must NOT satisfy threshold"
        );

        // Wrong message — sigs valid but bound to a different digest.
        let other_hash = [0xEF; 32];
        let witness_ab_wrong = DescriptorWitness {
            stack: vec![sign_message(&sk_a, &msg_hash).to_vec(), sign_message(&sk_b, &msg_hash).to_vec()],
        };
        assert!(
            !verify_witness(&descriptor, &witness_ab_wrong, &other_hash).unwrap(),
            "2-of-3: sigs over wrong message must NOT satisfy"
        );
    }
}
