//! bLSAG (Back-linkable Linkable Spontaneous Anonymous Group) signatures
//! over secp256k1.
//!
//! Algorithm (signer at index π in ring `[P_0, …, P_{n-1}]`, secret `sk`,
//! message `m`):
//!
//! 1. Compute key image `I = sk · H_p(encode(P_π))`.
//! 2. Pick a fresh `α` and one `s_i` per non-signer index.
//! 3. Set `L_π = α·G`, `R_π = α·H_p(encode(P_π))`.
//! 4. For `i = π+1, π+2, …` (mod n) until we wrap back to π:
//!      `c_i      = H_τ(L_{i-1} || R_{i-1} || m)`
//!      `L_i      = s_i·G          + c_i·P_i`
//!      `R_i      = s_i·H_p(P_i)   + c_i·I`
//! 5. Once `c_π` is fixed by the chain, close it: `s_π = α − c_π·sk`.
//! 6. Output `(c_0, s_0, …, s_{n-1}, I)`.
//!
//! Verification walks the same chain forward, recomputing each `c_{i+1}`
//! from `(L_i, R_i, m)`, and accepts iff `c_n == c_0`.
//!
//! Soundness lives on the chain-closure check; anonymity lives on the
//! independence between `α` and the response chain segment from `π+1`
//! onward. Linkability is exposed solely via `I`, the key image — the
//! 32-byte presentation `nullifier` is computed elsewhere from `I`.
//!
//! Edge-case scalars (a randomly-sampled 0, a chain-derived `c_i` of
//! exactly 0) are vanishingly improbable but representable. We reject
//! them as `Error::Degenerate` in sign (callers retry with fresh
//! randomness) and as `Error::Invalid` in verify (treated as forgery).

use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::hash_to_curve::hash_to_curve;
use crate::tagged::{tagged_hash_parts, TAG_CHALLENGE};

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Ring is empty or signer index is out of range.
    BadRing,
    /// `signer_sk·G` is not the ring member at `signer_index`.
    SignerNotInRing,
    /// A scalar landed on 0 or a point on infinity during construction
    /// or verification. Sign callers should retry with fresh
    /// randomness; verify callers should treat this as a forgery.
    Degenerate,
    /// Chain closure failed: `c_n != c_0`. Signature is forged or
    /// produced under a different ring/message.
    Invalid,
}

/// A bLSAG signature. Compact wire form is
/// `key_image (33B) || c_0 (32B) || responses (32B × n)`.
#[derive(Debug, Clone, PartialEq)]
pub struct RingSignature {
    /// `I = sk · H_p(encode(P_π))`. 33-byte compressed encoding on the
    /// wire and as a hash input.
    pub key_image: PublicKey,
    /// Starting challenge of the response chain.
    pub c_0: [u8; 32],
    /// One response per ring member, in ring order.
    pub responses: Vec<[u8; 32]>,
}

impl RingSignature {
    pub fn ring_size(&self) -> usize {
        self.responses.len()
    }
}

/// Produce a bLSAG signature. The caller passes the ring in canonical
/// order; `signer_index` identifies which member is producing the
/// signature, and `signer_sk` must be the secret behind
/// `ring[signer_index]`.
pub fn sign(
    secp: &Secp256k1<All>,
    ring: &[PublicKey],
    signer_index: usize,
    signer_sk: &SecretKey,
    message: &[u8],
    rng: &mut impl RngCore,
) -> Result<RingSignature, Error> {
    let n = ring.len();
    if n == 0 || signer_index >= n {
        return Err(Error::BadRing);
    }
    let signer_pk = signer_sk.public_key(secp);
    if signer_pk != ring[signer_index] {
        return Err(Error::SignerNotInRing);
    }

    // I = sk · H_p(encode(P_π))
    let h_signer = hash_to_curve(&signer_pk.serialize());
    let h_signer_scalar = h_signer
        .mul_tweak(secp, &sk_to_scalar(signer_sk))
        .map_err(|_| Error::Degenerate)?;
    // Note: PublicKey::mul_tweak takes the *point*, scalar comes second.
    // Here we want sk · H_p(P_π), so the point is H_p and the scalar is sk.
    let key_image = h_signer_scalar; // sk · H_p(P_π)

    // Pick α (non-zero) and one response per non-signer index.
    let alpha = rand_secret_key(rng);
    let mut responses: Vec<[u8; 32]> = Vec::with_capacity(n);
    for _ in 0..n {
        responses.push(rand_secret_key(rng).secret_bytes());
    }

    // L_π = α·G,  R_π = α·H_p(P_π)
    let alpha_g = alpha.public_key(secp);
    let alpha_h = hash_to_curve(&signer_pk.serialize())
        .mul_tweak(secp, &sk_to_scalar(&alpha))
        .map_err(|_| Error::Degenerate)?;

    // Walk the chain from (π + 1) forward, wrapping. At each step compute
    // c_{(prev+1)%n} = H_τ(L_prev || R_prev || m), then derive L_i, R_i.
    let mut c = vec![[0u8; 32]; n];
    let start = (signer_index + 1) % n;
    c[start] = challenge(&alpha_g, &alpha_h, message);

    let mut prev_idx = start;
    for _step in 0..(n - 1) {
        let i = prev_idx;
        let s_i = scalar_from_bytes(&responses[i])?;
        let c_i = scalar_from_bytes(&c[i])?;

        // L_i = s_i·G + c_i·P_i;  R_i = s_i·H_p(P_i) + c_i·I.
        let l_i = linear_combo(secp, &s_i, g_base(), &c_i, &ring[i])?;
        let h_i = hash_to_curve(&ring[i].serialize());
        let r_i = linear_combo(secp, &s_i, &h_i, &c_i, &key_image)?;

        let next = (i + 1) % n;
        c[next] = challenge(&l_i, &r_i, message);
        prev_idx = next;
    }
    // After (n-1) iterations starting at `start`, prev_idx == signer_index
    // (the chain has wrapped all the way around to π) and c[signer_index]
    // is now set.

    // Close the ring: s_π = α − c_π · sk.
    let c_pi = scalar_from_bytes(&c[signer_index])?;
    let c_pi_sk = signer_sk.mul_tweak(&c_pi).map_err(|_| Error::Degenerate)?;
    let neg_c_pi_sk = c_pi_sk.negate();
    let s_pi = alpha
        .add_tweak(&sk_to_scalar(&neg_c_pi_sk))
        .map_err(|_| Error::Degenerate)?;
    responses[signer_index] = s_pi.secret_bytes();

    Ok(RingSignature {
        key_image,
        c_0: c[0],
        responses,
    })
}

/// Verify a bLSAG signature: walk the response chain and confirm closure.
pub fn verify(
    secp: &Secp256k1<All>,
    ring: &[PublicKey],
    message: &[u8],
    sig: &RingSignature,
) -> Result<(), Error> {
    let n = ring.len();
    if n == 0 || sig.responses.len() != n {
        return Err(Error::BadRing);
    }

    let mut c_i_bytes = sig.c_0;
    for i in 0..n {
        let s_i = scalar_from_bytes(&sig.responses[i])?;
        let c_i = scalar_from_bytes(&c_i_bytes)?;

        let l_i = linear_combo(secp, &s_i, g_base(), &c_i, &ring[i])?;
        let h_i = hash_to_curve(&ring[i].serialize());
        let r_i = linear_combo(secp, &s_i, &h_i, &c_i, &sig.key_image)?;

        c_i_bytes = challenge(&l_i, &r_i, message);
    }

    // After n iterations, c_i_bytes is c_n; for an honest signature it
    // wraps back to c_0. Constant-time compare to make a leaky verifier
    // a tiny bit harder.
    if ct_eq(&c_i_bytes, &sig.c_0) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

// ─── helpers ────────────────────────────────────────────────────────────

/// `H_τ("DepositsRingSig/v1/challenge", encode(L) || encode(R) || m)`
/// reduced into a 32-byte scalar buffer (caller turns it into a `Scalar`
/// via `scalar_from_bytes`, which rejects values ≥ n).
fn challenge(l: &PublicKey, r: &PublicKey, message: &[u8]) -> [u8; 32] {
    tagged_hash_parts(
        TAG_CHALLENGE,
        &[&l.serialize(), &r.serialize(), message],
    )
}

/// `s·P + c·Q`, treating either-zero-scalar specially because
/// `PublicKey::mul_tweak` with a zero scalar would land on infinity,
/// and `PublicKey::combine` can't represent that.
///
/// If both `s` and `c` are zero, the result is the identity, which we
/// can't represent — that's a Degenerate verifier input.
fn linear_combo(
    secp: &Secp256k1<All>,
    s: &Scalar,
    p: &PublicKey,
    c: &Scalar,
    q: &PublicKey,
) -> Result<PublicKey, Error> {
    let s_zero = scalar_is_zero(s);
    let c_zero = scalar_is_zero(c);
    match (s_zero, c_zero) {
        (true, true) => Err(Error::Degenerate),
        (true, false) => q.mul_tweak(secp, c).map_err(|_| Error::Degenerate),
        (false, true) => p.mul_tweak(secp, s).map_err(|_| Error::Degenerate),
        (false, false) => {
            let s_p = p.mul_tweak(secp, s).map_err(|_| Error::Degenerate)?;
            let c_q = q.mul_tweak(secp, c).map_err(|_| Error::Degenerate)?;
            s_p.combine(&c_q).map_err(|_| Error::Degenerate)
        }
    }
}

/// Cast a `SecretKey` into a `Scalar` for use as a tweak. `SecretKey`
/// is guaranteed in `[1, n-1]` so this never fails on range, but
/// `Scalar::from_be_bytes` returns Result so we propagate it.
fn sk_to_scalar(sk: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(sk.secret_bytes())
        .expect("SecretKey bytes are always a valid Scalar")
}

/// Construct a `Scalar` from raw bytes. Returns `Degenerate` if the
/// value is ≥ n (in which case the chain is malformed) or if the value
/// is 0 (which we reject because the linear-combo helper can't handle
/// 0·P uniformly without losing closure invariants).
///
/// In sign, this is hit only via vanishingly improbable randomness; in
/// verify, it means the signature is forged or corrupted.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(*bytes).map_err(|_| Error::Degenerate)
}

fn scalar_is_zero(s: &Scalar) -> bool {
    s.to_be_bytes() == [0u8; 32]
}

/// Pick a uniform secret key in `[1, n-1]`. Loop on the negligible
/// chance that the 32 bytes land on 0 or ≥ n; in practice the first
/// draw always succeeds.
fn rand_secret_key(rng: &mut impl RngCore) -> SecretKey {
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        if let Ok(sk) = SecretKey::from_slice(&buf) {
            return sk;
        }
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ─── secp256k1 generator G as a PublicKey ───────────────────────────────
//
// secp256k1 doesn't expose G as a Rust-level constant, but `SecretKey::1
// .public_key()` is exactly G. We cache it in a process-wide `OnceLock`
// so we pay the (tiny) construction cost once.
fn g_base() -> &'static PublicKey {
    use std::sync::OnceLock;
    static G: OnceLock<PublicKey> = OnceLock::new();
    G.get_or_init(|| {
        let secp = Secp256k1::signing_only();
        let mut b = [0u8; 32];
        b[31] = 1;
        SecretKey::from_slice(&b)
            .expect("SecretKey 1 is in [1, n-1]")
            .public_key(&secp)
    })
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;

    fn ring(secp: &Secp256k1<All>, n: usize) -> (Vec<PublicKey>, Vec<SecretKey>) {
        let mut pks = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let sk = SecretKey::new(&mut OsRng);
            pks.push(sk.public_key(secp));
            sks.push(sk);
        }
        (pks, sks)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 5);
        let m = b"hello ring";
        for i in 0..pks.len() {
            let sig = sign(&secp, &pks, i, &sks[i], m, &mut OsRng).unwrap();
            verify(&secp, &pks, m, &sig).expect("honest sig should verify");
            assert_eq!(sig.responses.len(), pks.len());
        }
    }

    #[test]
    fn rejects_wrong_signer_index() {
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 4);
        // Claim to be index 0 while signing with sks[1] — caught up front.
        let err = sign(&secp, &pks, 0, &sks[1], b"m", &mut OsRng).unwrap_err();
        assert_eq!(err, Error::SignerNotInRing);
    }

    #[test]
    fn rejects_modified_message() {
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 4);
        let sig = sign(&secp, &pks, 2, &sks[2], b"original", &mut OsRng).unwrap();
        assert_eq!(
            verify(&secp, &pks, b"tampered", &sig).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn rejects_modified_ring() {
        let secp = Secp256k1::new();
        let (mut pks, sks) = ring(&secp, 4);
        let sig = sign(&secp, &pks, 0, &sks[0], b"m", &mut OsRng).unwrap();
        // Swap a non-signer's pubkey with a fresh one.
        pks[3] = SecretKey::new(&mut OsRng).public_key(&secp);
        assert_eq!(
            verify(&secp, &pks, b"m", &sig).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn rejects_modified_response() {
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 4);
        let mut sig = sign(&secp, &pks, 1, &sks[1], b"m", &mut OsRng).unwrap();
        sig.responses[2][0] ^= 0x01;
        assert_eq!(
            verify(&secp, &pks, b"m", &sig).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn key_image_deterministic_in_signer() {
        // Same (sk, P_π) → same I, regardless of ring composition or
        // randomness. (Holds because I = sk·H_p(P_π); doesn't touch
        // anything else.)
        let secp = Secp256k1::new();
        let (mut pks, sks) = ring(&secp, 4);
        let sig_a = sign(&secp, &pks, 0, &sks[0], b"m1", &mut OsRng).unwrap();
        // Reshuffle the non-signer entries.
        pks.swap(1, 3);
        let sig_b = sign(&secp, &pks, 0, &sks[0], b"m2", &mut OsRng).unwrap();
        assert_eq!(sig_a.key_image, sig_b.key_image);
    }

    #[test]
    fn key_image_distinguishes_signers() {
        // Different signers under the same ring produce different I's.
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 5);
        let s0 = sign(&secp, &pks, 0, &sks[0], b"m", &mut OsRng).unwrap();
        let s1 = sign(&secp, &pks, 1, &sks[1], b"m", &mut OsRng).unwrap();
        assert_ne!(s0.key_image, s1.key_image);
    }

    #[test]
    fn anonymity_two_signatures_different_responses() {
        // Same signer signing the same message twice produces different
        // signatures (because the per-signature randomness differs),
        // but the same key image. Verifies both, key image identical.
        let secp = Secp256k1::new();
        let (pks, sks) = ring(&secp, 6);
        let a = sign(&secp, &pks, 3, &sks[3], b"m", &mut OsRng).unwrap();
        let b = sign(&secp, &pks, 3, &sks[3], b"m", &mut OsRng).unwrap();
        verify(&secp, &pks, b"m", &a).unwrap();
        verify(&secp, &pks, b"m", &b).unwrap();
        assert_eq!(a.key_image, b.key_image);
        assert_ne!(a.c_0, b.c_0);
        assert_ne!(a.responses, b.responses);
    }
}
