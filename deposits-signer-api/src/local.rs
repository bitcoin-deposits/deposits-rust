//! In-process signer that holds a `SecretKey`. Matches the daemon's pre-refactor
//! behaviour bit-for-bit so phase-3 call-site refactors are mechanical.

use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};

use crate::{SignContext, Signer, SignerError};

/// `Signer` impl that holds a single `SecretKey` in process.
///
/// Constructed from the operator/identity secret the daemon already derives
/// (`m/86'/0'/0'/0/0` from the seed; see
/// `deposits-node/src/node_cli/mod.rs::derive_operator_secret`). Phase-2 keeps
/// derivation in the daemon — `deposits-signer-api` doesn't take a seed.
pub struct LocalSigner {
    secret: SecretKey,
    pubkey: PublicKey,
    xonly: XOnlyPublicKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl LocalSigner {
    /// Build a signer from a derived operator/identity secret.
    pub fn new(secret: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        let (xonly, _parity) = pubkey.x_only_public_key();
        Self {
            secret,
            pubkey,
            xonly,
            secp,
        }
    }

    /// Test/dev helper: a signer with a fresh random secret.
    pub fn random() -> Self {
        use secp256k1::rand::rngs::OsRng;
        let secp = Secp256k1::new();
        let (secret_local, _) = secp.generate_keypair(&mut OsRng);
        // Convert from `secp256k1::SecretKey` to `bitcoin::secp256k1::SecretKey`.
        // Same underlying bytes; the two crates are identical at the wire level.
        let secret = SecretKey::from_slice(&secret_local.secret_bytes())
            .expect("secp256k1 keygen produced a valid secret");
        Self::new(secret)
    }
}

impl Signer for LocalSigner {
    fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    fn xonly_pubkey(&self) -> XOnlyPublicKey {
        self.xonly
    }

    fn bip340_sign(
        &self,
        _ctx: &SignContext,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError> {
        let msg = Message::from_digest(*digest);
        let keypair = Keypair::from_secret_key(&self.secp, &self.secret);
        // No aux rand to match the daemon's existing behaviour. The protocol
        // commits to BIP-340 sigs that verify; deterministic signing is fine
        // and avoids a live-RNG dependency in the signer hot path.
        Ok(self
            .secp
            .sign_schnorr_no_aux_rand(&msg, &keypair)
            .serialize())
    }

    fn ecdsa_sign_sighash(
        &self,
        _ctx: &SignContext,
        sighash: &[u8; 32],
    ) -> Result<ecdsa::Signature, SignerError> {
        let msg = Message::from_digest(*sighash);
        Ok(self.secp.sign_ecdsa(&msg, &self.secret))
    }

    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        let shared = SharedSecret::new(peer, &self.secret);
        Ok(shared.secret_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigPurpose, SigRole, SignContext};
    use bitcoin::secp256k1::Secp256k1;

    fn ctx() -> SignContext {
        SignContext {
            role: SigRole::NoLedger,
            purpose: SigPurpose::Bip340Untagged,
        }
    }

    #[test]
    fn pubkey_round_trip() {
        let signer = LocalSigner::random();
        let pk = signer.pubkey();
        let xonly = signer.xonly_pubkey();
        assert_eq!(pk.x_only_public_key().0, xonly);
    }

    #[test]
    fn bip340_sig_verifies() {
        let signer = LocalSigner::random();
        let digest = [7u8; 32];
        let sig_bytes = signer.bip340_sign(&ctx(), &digest).unwrap();

        let secp = Secp256k1::verification_only();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
        let msg = Message::from_digest(digest);
        secp.verify_schnorr(&sig, &msg, &signer.xonly_pubkey())
            .expect("signature should verify against signer's xonly pubkey");
    }

    #[test]
    fn bip340_sig_is_deterministic() {
        // We use sign_schnorr_no_aux_rand — same digest produces same sig.
        let signer = LocalSigner::random();
        let digest = [42u8; 32];
        let s1 = signer.bip340_sign(&ctx(), &digest).unwrap();
        let s2 = signer.bip340_sign(&ctx(), &digest).unwrap();
        assert_eq!(s1, s2, "sign_schnorr_no_aux_rand must be deterministic");
    }

    #[test]
    fn ecdsa_sighash_verifies() {
        let signer = LocalSigner::random();
        let sighash = [11u8; 32];
        let sig = signer
            .ecdsa_sign_sighash(&ctx(), &sighash)
            .expect("sign succeeds");
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(sighash);
        secp.verify_ecdsa(&msg, &sig, &signer.pubkey())
            .expect("ecdsa sig should verify");
    }

    #[test]
    fn ecdh_is_symmetric() {
        let alice = LocalSigner::random();
        let bob = LocalSigner::random();
        let a_to_b = alice.ecdh(&bob.pubkey()).unwrap();
        let b_to_a = bob.ecdh(&alice.pubkey()).unwrap();
        assert_eq!(a_to_b, b_to_a, "ECDH must be symmetric");
    }
}
