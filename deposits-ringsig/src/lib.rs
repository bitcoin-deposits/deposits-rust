//! bLSAG ring signatures over secp256k1, per the project's NIP-XX
//! ("Anonymous Web-of-Trust Requests"). See `RING-SIGNATURES.md` at the
//! repo root for the wire-format and verification spec.
//!
//! What this crate provides:
//!
//! - `tagged`: BIP-340-style tagged hashes with per-purpose tags
//!   (`hash-to-curve`, `challenge`, `nullifier`, `binding`).
//! - `hash_to_curve`: try-and-increment hash-to-secp256k1-point. Inputs
//!   are public, so the variable timing is acceptable.
//! - `blsag`: ring-signature `sign`/`verify`, key-image construction,
//!   `RingSignature` wire type. Linkability lives on the key image; the
//!   32-byte presentation `nullifier` (computed by `presentation_nullifier`
//!   below) is just a hash-of-`I` for indexing.
//!
//! Not yet implemented in this crate (planned alongside the verifier and
//! wallet integrations):
//!
//! - The bound-pubkey binding proof (Sigma protocol joining `I` and a
//!   fresh `P` to the same `sk`).
//! - Cover / first-contact / continuation event types and JSON serde.

pub mod binding;
pub mod blsag;
pub mod hash_to_curve;
pub mod tagged;
pub mod wire;

pub use blsag::{sign, verify, Error, RingSignature};
pub use hash_to_curve::hash_to_curve as hash_point;

use bitcoin::secp256k1::PublicKey;

/// Compute the 32-byte presentation nullifier from the ring-signature
/// key image and a context separator.
///
/// `ctx` is `<anchor_pubkey_hex>/<cover_d_tag>` per the NIP. This hash
/// gives external observers an indexable handle that's unlinkable across
/// `(anchor, cover)` pairs without correlating the underlying `I`.
///
/// Linkability — the property the verifier actually relies on for
/// double-spend detection — lives on `I` itself, not on this hash. See
/// `RING-SIGNATURES.md` "Privacy Considerations" for the caveat.
pub fn presentation_nullifier(key_image: &PublicKey, ctx: &[u8]) -> [u8; 32] {
    tagged::tagged_hash_parts(tagged::TAG_NULLIFIER, &[&key_image.serialize(), ctx])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};

    #[test]
    fn presentation_nullifier_changes_with_ctx() {
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let sig = blsag::sign(&secp, &pks, 1, &sks[1], b"m", &mut OsRng).unwrap();
        let n_a = presentation_nullifier(&sig.key_image, b"anchor1/cover1");
        let n_b = presentation_nullifier(&sig.key_image, b"anchor1/cover2");
        let n_c = presentation_nullifier(&sig.key_image, b"anchor2/cover1");
        assert_ne!(n_a, n_b);
        assert_ne!(n_a, n_c);
        assert_ne!(n_b, n_c);
    }

    #[test]
    fn presentation_nullifier_stable_for_same_ctx() {
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        // Two signatures from the same signer in the same ring.
        let s1 = blsag::sign(&secp, &pks, 0, &sks[0], b"m1", &mut OsRng).unwrap();
        let s2 = blsag::sign(&secp, &pks, 0, &sks[0], b"m2", &mut OsRng).unwrap();
        // Key images match — that's the linkability property.
        assert_eq!(s1.key_image, s2.key_image);
        // Therefore so do the presentation nullifiers under the same ctx.
        let ctx = b"a/c";
        assert_eq!(
            presentation_nullifier(&s1.key_image, ctx),
            presentation_nullifier(&s2.key_image, ctx),
        );
    }
}
