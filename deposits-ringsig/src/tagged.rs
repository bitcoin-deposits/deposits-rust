//! BIP-340 tagged hashes.
//!
//! `H_τ(data) = SHA256(SHA256(τ) || SHA256(τ) || data)`, where `τ` is a
//! purpose-specific UTF-8 string. Using tagged hashes everywhere makes
//! it impossible for a hash output produced under one tag to be mistaken
//! for one produced under another, even if the underlying message bytes
//! happen to coincide.

use sha2::{Digest, Sha256};

/// Tag for the hash-to-curve seed (try-and-increment).
pub const TAG_HASH_TO_CURVE: &[u8] = b"DepositsRingSig/v1/hash-to-curve";

/// Tag for the bLSAG challenge chain.
pub const TAG_CHALLENGE: &[u8] = b"DepositsRingSig/v1/challenge";

/// Tag for the published 32-byte presentation nullifier.
/// Underlying linkability is on the 33-byte compressed key image `I`.
pub const TAG_NULLIFIER: &[u8] = b"DepositsRingSig/v1/nullifier";

/// Tag for the bound-pubkey binding proof challenge.
pub const TAG_BINDING: &[u8] = b"DepositsRingSig/v1/binding";

/// Compute `H_τ(data)`.
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // h_tag = SHA256(τ); the BIP-340 trick prefixes data with two
    // copies of h_tag so the inner SHA-256 block is fully consumed
    // and the construction is domain-separated even if a different
    // implementation happens to call SHA-256(data) directly.
    let h_tag = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(h_tag);
    hasher.update(h_tag);
    hasher.update(data);
    hasher.finalize().into()
}

/// Equivalent to `tagged_hash` but accepts the data as multiple
/// fragments, mirroring `Hasher::update` ergonomics. Avoids an
/// intermediate concat allocation in callers that build up the hash
/// input from several fixed-size pieces.
pub fn tagged_hash_parts(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let h_tag = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(h_tag);
    hasher.update(h_tag);
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_bip340_construction() {
        // SHA256(SHA256(tag) || SHA256(tag) || data)
        let tag = b"test-tag";
        let data = b"hello";
        let want = {
            let h = Sha256::digest(tag);
            let mut hasher = Sha256::new();
            hasher.update(h);
            hasher.update(h);
            hasher.update(data);
            hasher.finalize()
        };
        assert_eq!(tagged_hash(tag, data).as_slice(), want.as_slice());
    }

    #[test]
    fn different_tags_diverge_for_same_data() {
        let a = tagged_hash(b"tag-a", b"data");
        let b = tagged_hash(b"tag-b", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn different_data_diverges_under_same_tag() {
        let a = tagged_hash(b"tag", b"data-a");
        let b = tagged_hash(b"tag", b"data-b");
        assert_ne!(a, b);
    }

    #[test]
    fn parts_equal_concat() {
        let single = tagged_hash(b"tag", b"abc");
        let split = tagged_hash_parts(b"tag", &[b"a", b"bc"]);
        assert_eq!(single, split);
    }
}
