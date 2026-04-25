//! Hash-to-curve for secp256k1 via try-and-increment.
//!
//! Repeatedly seeds a tagged hash with `(input || u32-le counter)`, treats
//! the 32-byte output as an affine x-coordinate, and tries to lift it to a
//! point with even y (BIP-340 style). On failure, increment the counter and
//! retry. Expected iterations ≈ 2 (each candidate has a ~½ chance of being
//! a valid x).
//!
//! The variable timing of try-and-increment is acceptable here: the input
//! to `H_p` is exclusively public material — a ring member's compressed
//! pubkey — so the iteration count leaks nothing about the signer's
//! secret. Don't reuse this primitive in contexts where the input is
//! secret without re-evaluating that assumption.

use bitcoin::secp256k1::PublicKey;

use crate::tagged::{tagged_hash_parts, TAG_HASH_TO_CURVE};

/// Map an arbitrary byte string to a secp256k1 point. Returns the
/// even-y lift of the first valid candidate x-coordinate.
///
/// Practically never iterates more than a handful of times. We cap at
/// 256 attempts as a defense-in-depth — if the first 256 candidates
/// all miss the curve, something is structurally wrong (probability
/// ≈ 2^-256) and panicking is preferable to spinning forever.
pub fn hash_to_curve(input: &[u8]) -> PublicKey {
    let mut candidate = [0u8; 33];
    candidate[0] = 0x02; // even-y prefix
    for counter in 0u32..256 {
        let x = tagged_hash_parts(TAG_HASH_TO_CURVE, &[input, &counter.to_le_bytes()]);
        candidate[1..].copy_from_slice(&x);
        if let Ok(pk) = PublicKey::from_slice(&candidate) {
            return pk;
        }
    }
    // 256 consecutive misses is statistically impossible; if it
    // happens, the input or the curve is broken.
    panic!("hash_to_curve: 256 candidates rejected — broken input or curve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn deterministic() {
        let a = hash_to_curve(b"test");
        let b = hash_to_curve(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_yield_distinct_points() {
        let a = hash_to_curve(b"alpha");
        let b = hash_to_curve(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn output_lies_on_curve() {
        // PublicKey::from_slice already enforces this — we just
        // exercise that the result round-trips through serialization.
        let p = hash_to_curve(b"check");
        let bytes = p.serialize();
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 0x02, "even-y prefix expected");
        let p2 = PublicKey::from_slice(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn output_independent_of_secp_signing_context() {
        // Ensure the function doesn't accidentally depend on a
        // signing-only / verification-only context — it shouldn't,
        // we don't sign or verify in here.
        let _ = Secp256k1::new();
        let p = hash_to_curve(b"x");
        assert_eq!(p, hash_to_curve(b"x"));
    }
}
