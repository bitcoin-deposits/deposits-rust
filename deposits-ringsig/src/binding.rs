//! Bound-pubkey binding proof.
//!
//! At first contact (NIP kind 21XXX) the requester declares a fresh
//! `P = sk_P · G` that they'll use for cheap Schnorr-signed continuation
//! requests. Without a binding proof, anyone could grab someone else's
//! `P` from the wire, slap it onto their own ring signature, and nudge
//! the verifier into recording `(I_attacker, P_victim)` — a small DoS
//! against the verifier's pseudonym table, even though the attacker
//! still couldn't sign continuations under `P` (they don't have
//! `sk_P`). The binding proof closes that gap by requiring the first-
//! contact author to demonstrate knowledge of `sk_P`.
//!
//! Construction is a standard Schnorr Σ-protocol for "I know `sk_P`
//! such that `P = sk_P·G`", made non-interactive via Fiat-Shamir. The
//! challenge folds in the surrounding ring signature's `c_0` and key
//! image `I`, so a valid `(R, s)` pair is good for *exactly* that ring-
//! signed event — replay across different first-contact events fails.

use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::blsag::{Error, RingSignature};
use crate::tagged::{tagged_hash_parts, TAG_BINDING};

/// Schnorr proof of knowledge of `sk_P` for a declared bound pubkey `P`.
/// Wire form: 33-byte compressed `R` followed by 32-byte `s`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundPubkeyProof {
    /// Schnorr commitment `R = α · G`.
    pub r: PublicKey,
    /// Response `s = α + c · sk_P` (mod n).
    pub s: [u8; 32],
}

/// Build the Fiat-Shamir challenge.
///
/// Folding in `c_0` and `I` (both already present in the ring signature)
/// is what binds this proof to a specific first-contact event. Anyone
/// substituting a different ring sig recomputes a different `c_bind` and
/// the verification equation no longer holds.
fn challenge(p: &PublicKey, r: &PublicKey, ring: &RingSignature) -> [u8; 32] {
    tagged_hash_parts(
        TAG_BINDING,
        &[
            &p.serialize(),
            &r.serialize(),
            &ring.c_0,
            &ring.key_image.serialize(),
        ],
    )
}

/// Produce a binding proof for `P = sk_p · G` against the given ring
/// signature. The caller has just produced (or is about to publish) the
/// ring signature; the proof commits to it via `c_0` and `I`.
pub fn prove(
    secp: &Secp256k1<All>,
    sk_p: &SecretKey,
    ring: &RingSignature,
    rng: &mut impl RngCore,
) -> Result<BoundPubkeyProof, Error> {
    let p = sk_p.public_key(secp);
    let alpha = rand_secret_key(rng);
    let r = alpha.public_key(secp);
    let c = challenge(&p, &r, ring);
    let c_scalar = Scalar::from_be_bytes(c).map_err(|_| Error::Degenerate)?;

    // s = α + c · sk_P. Compute c·sk_P first, then add α.
    let c_sk = sk_p.mul_tweak(&c_scalar).map_err(|_| Error::Degenerate)?;
    let c_sk_scalar = Scalar::from_be_bytes(c_sk.secret_bytes())
        .expect("SecretKey bytes are always a valid Scalar");
    let s = alpha
        .add_tweak(&c_sk_scalar)
        .map_err(|_| Error::Degenerate)?;

    Ok(BoundPubkeyProof {
        r,
        s: s.secret_bytes(),
    })
}

/// Verify the binding proof: `s·G ?= R + c · P`, where `c` folds in
/// the ring signature's `c_0` and `I`.
pub fn verify(
    secp: &Secp256k1<All>,
    p: &PublicKey,
    ring: &RingSignature,
    proof: &BoundPubkeyProof,
) -> Result<(), Error> {
    let c = challenge(p, &proof.r, ring);
    let c_scalar = Scalar::from_be_bytes(c).map_err(|_| Error::Degenerate)?;

    // c · P
    let c_p = p
        .mul_tweak(secp, &c_scalar)
        .map_err(|_| Error::Degenerate)?;
    // R + c·P
    let expected = proof.r.combine(&c_p).map_err(|_| Error::Degenerate)?;

    // s · G — `SecretKey::from_slice` rejects the zero scalar; if `s`
    // is zero, the proof is invalid (no honest signature lands on it
    // because `α` is random).
    let s_sk = SecretKey::from_slice(&proof.s).map_err(|_| Error::Degenerate)?;
    let s_g = s_sk.public_key(secp);

    // Constant-time compare of the 33-byte compressed encodings.
    let a = s_g.serialize();
    let b = expected.serialize();
    let mut diff = 0u8;
    for i in 0..33 {
        diff |= a[i] ^ b[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

fn rand_secret_key(rng: &mut impl RngCore) -> SecretKey {
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        if let Ok(sk) = SecretKey::from_slice(&buf) {
            return sk;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blsag;
    use bitcoin::secp256k1::rand::rngs::OsRng;

    fn ring_and_sig(
        secp: &Secp256k1<All>,
        n: usize,
        signer: usize,
    ) -> (Vec<PublicKey>, RingSignature) {
        let mut sks = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);
        for _ in 0..n {
            let sk = SecretKey::new(&mut OsRng);
            pks.push(sk.public_key(secp));
            sks.push(sk);
        }
        let sig = blsag::sign(
            secp,
            &pks,
            signer,
            &sks[signer],
            b"first-contact",
            &mut OsRng,
        )
        .expect("ring sig");
        (pks, sig)
    }

    #[test]
    fn prove_verify_round_trip() {
        let secp = Secp256k1::new();
        let (_pks, ring) = ring_and_sig(&secp, 5, 2);

        let sk_p = SecretKey::new(&mut OsRng);
        let p = sk_p.public_key(&secp);
        let proof = prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();
        verify(&secp, &p, &ring, &proof).expect("honest binding should verify");
    }

    #[test]
    fn rejects_wrong_pubkey() {
        let secp = Secp256k1::new();
        let (_pks, ring) = ring_and_sig(&secp, 5, 0);
        let sk_p = SecretKey::new(&mut OsRng);
        let proof = prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();

        // Verify against a different P.
        let other_p = SecretKey::new(&mut OsRng).public_key(&secp);
        assert_eq!(
            verify(&secp, &other_p, &ring, &proof).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn rejects_replay_across_ring_sigs() {
        // Same (sk_P, P), two different ring sigs. The proof bound to
        // ring_a must not validate against ring_b.
        let secp = Secp256k1::new();
        let (_pks_a, ring_a) = ring_and_sig(&secp, 4, 1);
        let (_pks_b, ring_b) = ring_and_sig(&secp, 4, 1);
        let sk_p = SecretKey::new(&mut OsRng);
        let p = sk_p.public_key(&secp);

        let proof = prove(&secp, &sk_p, &ring_a, &mut OsRng).unwrap();
        verify(&secp, &p, &ring_a, &proof).expect("validates under its own ring sig");
        assert_eq!(
            verify(&secp, &p, &ring_b, &proof).unwrap_err(),
            Error::Invalid,
            "proof should not replay onto a different ring sig"
        );
    }

    #[test]
    fn rejects_modified_response() {
        let secp = Secp256k1::new();
        let (_pks, ring) = ring_and_sig(&secp, 5, 3);
        let sk_p = SecretKey::new(&mut OsRng);
        let p = sk_p.public_key(&secp);
        let mut proof = prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();
        proof.s[0] ^= 0x01;
        assert_eq!(
            verify(&secp, &p, &ring, &proof).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn rejects_modified_commitment() {
        let secp = Secp256k1::new();
        let (_pks, ring) = ring_and_sig(&secp, 5, 0);
        let sk_p = SecretKey::new(&mut OsRng);
        let p = sk_p.public_key(&secp);
        let proof_a = prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();
        let proof_b = prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();
        // Splice a's response onto b's commitment — different α so the
        // verification equation breaks.
        let frankenproof = BoundPubkeyProof {
            r: proof_b.r,
            s: proof_a.s,
        };
        assert_eq!(
            verify(&secp, &p, &ring, &frankenproof).unwrap_err(),
            Error::Invalid
        );
    }
}
