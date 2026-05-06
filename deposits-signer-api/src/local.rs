//! In-process signer that holds a `SecretKey`. Matches the daemon's pre-refactor
//! behaviour bit-for-bit so phase-3 call-site refactors are mechanical.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use std::str::FromStr;

use crate::{KeyPath, SignContext, Signer, SignerError};

/// `Signer` impl that holds a single `SecretKey` in process.
///
/// Constructed from the operator/identity secret the daemon already derives
/// (`m/86'/0'/0'/0/0` from the seed; see
/// `deposits-node/src/node_cli/mod.rs::derive_operator_secret`). Phase-2 keeps
/// derivation in the daemon — `deposits-signer-api` doesn't take a seed.
pub struct LocalSigner {
    /// Operator/identity key. Always present; this is what `pubkey()` reports.
    secret: SecretKey,
    pubkey: PublicKey,
    xonly: XOnlyPublicKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    /// Sibling-derived Nostr identity secret, if the signer was constructed
    /// to issue one. See [`Signer::issue_nostr_secret`].
    nostr_secret: Option<SecretKey>,
    /// Master xpriv, populated when the signer was built via [`from_xpriv`]
    /// or [`from_xpriv_with_nostr`]. Required to honour `KeyPath::Deposit
    /// { index }` requests — the per-deposit key is derived on demand from
    /// `m/84'/0'/0'/0/{index}`. Constructions via [`new`] or
    /// [`with_nostr_secret`] leave this `None` and refuse non-`Operator`
    /// key paths with `SignerError::Unsupported`.
    xpriv: Option<Xpriv>,
}

impl LocalSigner {
    /// Build a signer from a derived operator/identity secret.
    /// `issue_nostr_secret()` will return `Unsupported`. Sign requests
    /// with a non-`Operator` `KeyPath` will also fail — use
    /// [`from_xpriv`] for the depositor-key flows.
    pub fn new(secret: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        let (xonly, _parity) = pubkey.x_only_public_key();
        Self {
            secret,
            pubkey,
            xonly,
            secp,
            nostr_secret: None,
            xpriv: None,
        }
    }

    /// Build a signer from both an operator key and a sibling-derived Nostr
    /// identity key. The Nostr key is what `issue_nostr_secret()` returns.
    /// Caller is responsible for the BIP-32 derivation; `deposits-signer`'s
    /// data layer derives the Nostr key at `m/85'/0'/0'/0/0` from the same
    /// seed the operator key (`m/86'/0'/0'/0/0`) comes from.
    pub fn with_nostr_secret(operator_secret: SecretKey, nostr_secret: SecretKey) -> Self {
        let mut s = Self::new(operator_secret);
        s.nostr_secret = Some(nostr_secret);
        s
    }

    /// Build a signer from a master `Xpriv`. The operator key is derived
    /// at `m/86'/0'/0'/0/0`. Subsequent sign requests can carry any
    /// `KeyPath` — `Deposit { index }` is derived on demand from this
    /// stored xpriv.
    ///
    /// This is the constructor a real `deposits-signer` process would use;
    /// `LocalSigner::new` stays for tests and call sites that are
    /// deliberately operator-key-only.
    pub fn from_xpriv(xpriv: Xpriv) -> Result<Self, SignerError> {
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let path = DerivationPath::from_str("m/86'/0'/0'/0/0")
            .map_err(|e| SignerError::Crypto(format!("operator path: {}", e)))?;
        let operator_xpriv = xpriv
            .derive_priv(&secp, &path)
            .map_err(|e| SignerError::Crypto(format!("derive operator: {}", e)))?;
        let secret = operator_xpriv.private_key;
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        let (xonly, _parity) = pubkey.x_only_public_key();
        Ok(Self {
            secret,
            pubkey,
            xonly,
            secp,
            nostr_secret: None,
            xpriv: Some(xpriv),
        })
    }

    /// Like [`from_xpriv`] but also caches a sibling-derived Nostr secret
    /// (`m/85'/0'/0'/0/0`) for `issue_nostr_secret()`.
    pub fn from_xpriv_with_nostr(xpriv: Xpriv) -> Result<Self, SignerError> {
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let nostr_path = DerivationPath::from_str("m/85'/0'/0'/0/0")
            .map_err(|e| SignerError::Crypto(format!("nostr path: {}", e)))?;
        let nostr_secret = xpriv
            .derive_priv(&secp, &nostr_path)
            .map_err(|e| SignerError::Crypto(format!("derive nostr: {}", e)))?
            .private_key;
        let mut s = Self::from_xpriv(xpriv)?;
        s.nostr_secret = Some(nostr_secret);
        Ok(s)
    }

    /// Resolve a `KeyPath` to a `SecretKey`. `Operator` returns the cached
    /// secret in O(1); `Deposit { index }` derives on demand and requires
    /// the signer was constructed with an `Xpriv`.
    fn resolve_key(&self, key: KeyPath) -> Result<SecretKey, SignerError> {
        match key {
            KeyPath::Operator => Ok(self.secret),
            KeyPath::Deposit { index } => {
                let xpriv = self.xpriv.as_ref().ok_or_else(|| {
                    SignerError::Unsupported(format!(
                        "this LocalSigner was not constructed with an Xpriv; \
                         cannot sign with KeyPath::Deposit {{ index: {} }}",
                        index
                    ))
                })?;
                let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))
                    .map_err(|e| {
                        SignerError::Crypto(format!("deposit path index={}: {}", index, e))
                    })?;
                let derived = xpriv.derive_priv(&self.secp, &path).map_err(|e| {
                    SignerError::Crypto(format!("derive deposit index={}: {}", index, e))
                })?;
                Ok(derived.private_key)
            }
            KeyPath::Wallet {
                account,
                change,
                index,
            } => {
                let xpriv = self.xpriv.as_ref().ok_or_else(|| {
                    SignerError::Unsupported(format!(
                        "this LocalSigner was not constructed with an Xpriv; \
                         cannot sign with KeyPath::Wallet {{ account: {}, change: {}, index: {} }}",
                        account, change, index
                    ))
                })?;
                if change > 1 {
                    return Err(SignerError::Crypto(format!(
                        "wallet change must be 0 or 1; got {}",
                        change
                    )));
                }
                let path = DerivationPath::from_str(&format!(
                    "m/86'/0'/{}'/{}/{}",
                    account, change, index
                ))
                .map_err(|e| {
                    SignerError::Crypto(format!(
                        "wallet path acct={} change={} idx={}: {}",
                        account, change, index, e
                    ))
                })?;
                let derived = xpriv.derive_priv(&self.secp, &path).map_err(|e| {
                    SignerError::Crypto(format!(
                        "derive wallet acct={} change={} idx={}: {}",
                        account, change, index, e
                    ))
                })?;
                Ok(derived.private_key)
            }
            KeyPath::NodeWallet { change, index } => {
                let xpriv = self.xpriv.as_ref().ok_or_else(|| {
                    SignerError::Unsupported(format!(
                        "this LocalSigner was not constructed with an Xpriv; \
                         cannot sign with KeyPath::NodeWallet {{ change: {}, index: {} }}",
                        change, index
                    ))
                })?;
                if change > 1 {
                    return Err(SignerError::Crypto(format!(
                        "node-wallet change must be 0 or 1; got {}",
                        change
                    )));
                }
                let path = DerivationPath::from_str(&format!("m/{}/{}", change, index))
                    .map_err(|e| {
                        SignerError::Crypto(format!(
                            "node-wallet path change={} idx={}: {}",
                            change, index, e
                        ))
                    })?;
                let derived = xpriv.derive_priv(&self.secp, &path).map_err(|e| {
                    SignerError::Crypto(format!(
                        "derive node-wallet change={} idx={}: {}",
                        change, index, e
                    ))
                })?;
                Ok(derived.private_key)
            }
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

    fn pubkey_at(&self, key_path: KeyPath) -> Result<PublicKey, SignerError> {
        // Operator path is the cached operator pubkey — O(1), no
        // derivation. Other paths derive via `resolve_key`, then
        // multiply by G to get the pubkey.
        match key_path {
            KeyPath::Operator => Ok(self.pubkey),
            other => {
                let secret = self.resolve_key(other)?;
                Ok(PublicKey::from_secret_key(&self.secp, &secret))
            }
        }
    }

    fn bip340_sign(
        &self,
        ctx: &SignContext,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError> {
        let secret = self.resolve_key(ctx.key)?;
        let msg = Message::from_digest(*digest);
        let keypair = Keypair::from_secret_key(&self.secp, &secret);
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
        ctx: &SignContext,
        sighash: &[u8; 32],
    ) -> Result<ecdsa::Signature, SignerError> {
        let secret = self.resolve_key(ctx.key)?;
        let msg = Message::from_digest(*sighash);
        Ok(self.secp.sign_ecdsa(&msg, &secret))
    }

    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        let shared = SharedSecret::new(peer, &self.secret);
        Ok(shared.secret_bytes())
    }

    fn nip04_shared_key(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        // Same derivation `nostr/util::generate_shared_key` performs:
        // ecdh::shared_secret_point yields the 64-byte point; NIP-04 uses
        // the first 32 (the X coordinate). No hashing.
        use bitcoin::secp256k1::ecdh::shared_secret_point;
        let ssp = shared_secret_point(peer, &self.secret);
        let mut out = [0u8; 32];
        out.copy_from_slice(&ssp[..32]);
        Ok(out)
    }

    fn issue_nostr_secret(&self) -> Result<[u8; 32], SignerError> {
        match self.nostr_secret {
            Some(sk) => Ok(sk.secret_bytes()),
            None => Err(SignerError::Unsupported(
                "this LocalSigner was not constructed with a Nostr secret".to_string(),
            )),
        }
    }

    fn wallet_account_xpub(&self, account: u32) -> Result<bitcoin::bip32::Xpub, SignerError> {
        let xpriv = self.xpriv.as_ref().ok_or_else(|| {
            SignerError::Unsupported(format!(
                "this LocalSigner was not constructed with an Xpriv; \
                 cannot issue wallet account xpub for account={}",
                account
            ))
        })?;
        let path = DerivationPath::from_str(&format!("m/86'/0'/{}'", account)).map_err(|e| {
            SignerError::Crypto(format!("wallet account path acct={}: {}", account, e))
        })?;
        let derived = xpriv.derive_priv(&self.secp, &path).map_err(|e| {
            SignerError::Crypto(format!("derive wallet account acct={}: {}", account, e))
        })?;
        Ok(bitcoin::bip32::Xpub::from_priv(&self.secp, &derived))
    }

    fn master_xpub(&self) -> Result<bitcoin::bip32::Xpub, SignerError> {
        let xpriv = self.xpriv.as_ref().ok_or_else(|| {
            SignerError::Unsupported(
                "this LocalSigner was not constructed with an Xpriv; \
                 cannot issue master xpub"
                    .to_string(),
            )
        })?;
        Ok(bitcoin::bip32::Xpub::from_priv(&self.secp, xpriv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigPurpose, SigRole, SignContext};
    use bitcoin::secp256k1::Secp256k1;

    fn ctx() -> SignContext {
        SignContext::no_ledger(SigPurpose::Bip340Untagged)
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

    #[test]
    fn nip04_shared_key_is_symmetric() {
        let alice = LocalSigner::random();
        let bob = LocalSigner::random();
        let a_to_b = alice.nip04_shared_key(&bob.pubkey()).unwrap();
        let b_to_a = bob.nip04_shared_key(&alice.pubkey()).unwrap();
        assert_eq!(a_to_b, b_to_a, "NIP-04 raw-X shared key must be symmetric");
    }

    #[test]
    fn nip04_shared_key_differs_from_hashed_ecdh() {
        // The two derivations of "ECDH shared secret" produce different
        // bytes — getting them mixed up yields unreadable ciphertext.
        // Lock the difference here so the wrong one can't sneak in.
        let alice = LocalSigner::random();
        let bob = LocalSigner::random();
        let raw_x = alice.nip04_shared_key(&bob.pubkey()).unwrap();
        let hashed = alice.ecdh(&bob.pubkey()).unwrap();
        assert_ne!(raw_x, hashed, "NIP-04 raw-X must differ from hashed ECDH");
    }

    #[test]
    fn nip04_shared_key_matches_secp256k1_shared_secret_point() {
        // Cross-check against the canonical derivation from the
        // secp256k1 crate. nostr/util::generate_shared_key uses the
        // same primitive; this test future-proofs against NIP-04
        // changing the convention out from under us.
        use bitcoin::secp256k1::ecdh::shared_secret_point;
        let alice = LocalSigner::random();
        let bob = LocalSigner::random();
        let from_signer = alice.nip04_shared_key(&bob.pubkey()).unwrap();
        let ssp = shared_secret_point(&bob.pubkey(), alice.secret_key_for_test());
        assert_eq!(&from_signer[..], &ssp[..32]);
    }

    #[test]
    fn new_signer_refuses_to_issue_nostr_secret() {
        let s = LocalSigner::random();
        let err = s.issue_nostr_secret().unwrap_err();
        assert!(matches!(err, SignerError::Unsupported(_)));
    }

    #[test]
    fn from_xpriv_signs_at_operator_path() {
        // Reproduce the same operator key the daemon's wallet derives, then
        // confirm a from_xpriv-built LocalSigner reports the same pubkey.
        use bitcoin::Network;
        let seed = [0xCC; 32];
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        let signer = LocalSigner::from_xpriv(xpriv).unwrap();
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let path = DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
        let expected = xpriv.derive_priv(&secp, &path).unwrap().private_key;
        let expected_pk = PublicKey::from_secret_key(&secp, &expected);
        assert_eq!(signer.pubkey(), expected_pk);
    }

    #[test]
    fn from_xpriv_signs_at_deposit_index() {
        // Signing at KeyPath::Deposit { index } uses the m/84' path —
        // matches what derive_deposit_key_at(index) in node_cli/keys.rs
        // produces.
        use bitcoin::Network;
        use crate::{KeyPath, SigPurpose, SignContext};

        let seed = [0xDD; 32];
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        let signer = LocalSigner::from_xpriv(xpriv).unwrap();

        let ctx = SignContext::deposit(7, SigPurpose::DepositGuarantee);
        let digest = [0x42u8; 32];
        let sig_bytes = signer.bip340_sign(&ctx, &digest).unwrap();

        // Derive expected key at m/84'/0'/0'/0/7 and verify against it.
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let path = DerivationPath::from_str("m/84'/0'/0'/0/7").unwrap();
        let expected_sk = xpriv.derive_priv(&secp, &path).unwrap().private_key;
        let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);
        let (expected_xonly, _) = expected_pk.x_only_public_key();

        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
        let msg = Message::from_digest(digest);
        secp.verify_schnorr(&sig, &msg, &expected_xonly)
            .expect("sig should verify against m/84'/0'/0'/0/7's xonly pubkey");
        // And the operator-key check should fail (sanity).
        assert!(
            secp.verify_schnorr(&sig, &msg, &signer.xonly_pubkey())
                .is_err(),
            "deposit-key sig must NOT verify against operator pubkey"
        );
    }

    #[test]
    fn new_signer_refuses_deposit_key_path() {
        use crate::{SigPurpose, SignContext};
        let signer = LocalSigner::random();
        let ctx = SignContext::deposit(0, SigPurpose::DepositGuarantee);
        let err = signer.bip340_sign(&ctx, &[0; 32]).unwrap_err();
        assert!(matches!(err, SignerError::Unsupported(_)));
    }

    #[test]
    fn deposit_key_indexes_are_distinct() {
        use bitcoin::Network;
        use crate::{SigPurpose, SignContext};

        let seed = [0xEE; 32];
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        let signer = LocalSigner::from_xpriv(xpriv).unwrap();

        // Different indexes → different sigs over the same digest.
        let digest = [0x99u8; 32];
        let s0 = signer
            .bip340_sign(&SignContext::deposit(0, SigPurpose::DepositGuarantee), &digest)
            .unwrap();
        let s1 = signer
            .bip340_sign(&SignContext::deposit(1, SigPurpose::DepositGuarantee), &digest)
            .unwrap();
        assert_ne!(s0, s1);
    }

    #[test]
    fn wallet_keypath_distinct_per_account_change_index() {
        use bitcoin::Network;
        use crate::{KeyPath, SigPurpose, SignContext};

        let seed = [0x77; 32];
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        let signer = LocalSigner::from_xpriv(xpriv).unwrap();

        let digest = [0x42u8; 32];
        let mut sigs = std::collections::HashSet::new();
        for account in 0..3u32 {
            for change in 0..2u8 {
                for index in 0..3u32 {
                    let ctx = SignContext {
                        role: crate::SigRole::NoLedger,
                        purpose: SigPurpose::Bip340Untagged,
                        key: KeyPath::Wallet { account, change, index },
                    };
                    let sig = signer.bip340_sign(&ctx, &digest).unwrap();
                    assert!(
                        sigs.insert(sig),
                        "duplicate sig for account={} change={} index={}",
                        account, change, index
                    );
                }
            }
        }
        assert_eq!(sigs.len(), 18);
    }

    #[test]
    fn wallet_keypath_rejects_invalid_change() {
        use bitcoin::Network;
        use crate::{KeyPath, SigPurpose, SignContext};

        let seed = [0x88; 32];
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        let signer = LocalSigner::from_xpriv(xpriv).unwrap();

        let ctx = SignContext {
            role: crate::SigRole::NoLedger,
            purpose: SigPurpose::Bip340Untagged,
            key: KeyPath::Wallet { account: 0, change: 2, index: 0 },
        };
        let err = signer.bip340_sign(&ctx, &[0u8; 32]).unwrap_err();
        assert!(
            format!("{:?}", err).contains("change must be 0 or 1"),
            "expected change-validation error, got: {:?}",
            err
        );
    }

    #[test]
    fn wallet_keypath_refused_without_xpriv() {
        use crate::{KeyPath, SigPurpose, SignContext};

        // Plain `LocalSigner::new` doesn't carry an Xpriv — only the
        // operator secret. Wallet-account paths require xpriv-aware
        // construction (`from_xpriv` or `from_xpriv_with_nostr`).
        let signer = LocalSigner::random();
        let ctx = SignContext {
            role: crate::SigRole::NoLedger,
            purpose: SigPurpose::Bip340Untagged,
            key: KeyPath::Wallet { account: 0, change: 0, index: 0 },
        };
        let err = signer.bip340_sign(&ctx, &[0u8; 32]).unwrap_err();
        assert!(
            format!("{:?}", err).contains("not constructed with an Xpriv"),
            "expected unsupported error, got: {:?}",
            err
        );
    }

    #[test]
    fn with_nostr_secret_returns_distinct_key() {
        let op = LocalSigner::random();
        let nostr = LocalSigner::random();
        let signer = LocalSigner::with_nostr_secret(*op.secret_key_for_test(), *nostr.secret_key_for_test());
        // Operator-side ops use the operator secret.
        assert_eq!(signer.pubkey(), op.pubkey());
        // The issued Nostr secret matches what we passed in (and is *not*
        // the operator secret).
        let issued = signer.issue_nostr_secret().unwrap();
        assert_eq!(issued, nostr.secret_key_for_test().secret_bytes());
        assert_ne!(issued, op.secret_key_for_test().secret_bytes());
    }
}

#[cfg(test)]
impl LocalSigner {
    /// Test-only accessor for the underlying operator secret. Not exposed
    /// outside `cfg(test)` — production code can't pull the secret back out.
    pub fn secret_key_for_test(&self) -> &SecretKey {
        &self.secret
    }
}
