// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Signer Implementation
//!
//! Implements the `SignatureProvider` trait using LDK's NodeSigner.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use deposits_core::traits::SignatureProvider;
use lightning::sign::NodeSigner;

use std::ops::Deref;
use std::sync::Arc;

/// LDK-based signer for Bitcoin Deposits protocol.
///
/// Uses the node's key for signing protocol messages.
pub struct LdkSigner<NS: Deref>
where
    NS::Target: NodeSigner,
{
    node_signer: Arc<NS>,
    secp: Secp256k1<secp256k1::All>,
}

impl<NS: Deref> LdkSigner<NS>
where
    NS::Target: NodeSigner,
{
    /// Create a new LDK signer adapter.
    pub fn new(node_signer: Arc<NS>) -> Self {
        Self {
            node_signer,
            secp: Secp256k1::new(),
        }
    }
}

impl<NS: Deref + Send + Sync> SignatureProvider for LdkSigner<NS>
where
    NS::Target: NodeSigner,
{
    fn node_pubkey(&self) -> PublicKey {
        self.node_signer.get_node_id(lightning::sign::Recipient::Node)
            .expect("Node ID should always be available")
    }

    fn sign_schnorr(&self, message_hash: [u8; 32]) -> Result<[u8; 64], String> {
        // LDK's NodeSigner doesn't directly expose Schnorr signing,
        // so we use sign_invoice which signs with the node key.
        // For a production implementation, you'd want to add Schnorr
        // signing support to the NodeSigner trait.

        // For now, use ECDSA signing and convert (this is a simplification)
        let _message = secp256k1::Message::from_digest(message_hash);

        // Sign using the node key - this requires access to the secret key
        // which NodeSigner doesn't expose directly for Schnorr.
        // In practice, you'd need to extend LDK's signer interface.

        // Placeholder: return an error indicating Schnorr not yet supported
        Err("Schnorr signing requires extended NodeSigner support".to_string())
    }

    fn verify_schnorr(
        &self,
        pubkey: &PublicKey,
        message_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        // Convert to x-only pubkey for Schnorr verification
        let (xonly, _parity) = pubkey.x_only_public_key();
        let message = secp256k1::Message::from_digest(message_hash);

        if let Ok(sig) = secp256k1::schnorr::Signature::from_slice(signature) {
            self.secp.verify_schnorr(&sig, &message, &xonly).is_ok()
        } else {
            false
        }
    }
}

/// In-memory signer for testing.
pub struct MemorySigner {
    secret_key: SecretKey,
    public_key: PublicKey,
    secp: Secp256k1<secp256k1::All>,
}

impl MemorySigner {
    /// Create a new test signer with a random key.
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Self {
            secret_key,
            public_key,
            secp,
        }
    }

    /// Create with a specific secret key.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&secret).map_err(|e| format!("Invalid secret key: {}", e))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(Self {
            secret_key,
            public_key,
            secp,
        })
    }
}

impl Default for MemorySigner {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureProvider for MemorySigner {
    fn node_pubkey(&self) -> PublicKey {
        self.public_key
    }

    fn sign_schnorr(&self, message_hash: [u8; 32]) -> Result<[u8; 64], String> {
        let keypair = secp256k1::Keypair::from_secret_key(&self.secp, &self.secret_key);
        let message = secp256k1::Message::from_digest(message_hash);

        let sig = self.secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(sig.serialize())
    }

    fn verify_schnorr(
        &self,
        pubkey: &PublicKey,
        message_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        let (xonly, _parity) = pubkey.x_only_public_key();
        let message = secp256k1::Message::from_digest(message_hash);

        if let Ok(sig) = secp256k1::schnorr::Signature::from_slice(signature) {
            self.secp.verify_schnorr(&sig, &message, &xonly).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_signer_pubkey() {
        let signer = MemorySigner::new();
        let pubkey = signer.node_pubkey();

        // Should be a valid pubkey
        assert_eq!(pubkey.serialize().len(), 33);
    }

    #[test]
    fn test_memory_signer_sign_verify() {
        let signer = MemorySigner::new();
        let message = [42u8; 32];

        // Sign
        let signature = signer.sign_schnorr(message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify with correct pubkey
        let pubkey = signer.node_pubkey();
        assert!(signer.verify_schnorr(&pubkey, message, &signature));

        // Verify fails with wrong message
        let wrong_message = [43u8; 32];
        assert!(!signer.verify_schnorr(&pubkey, wrong_message, &signature));
    }

    #[test]
    fn test_memory_signer_from_secret() {
        let secret = [5u8; 32];
        let signer1 = MemorySigner::from_secret(secret).unwrap();
        let signer2 = MemorySigner::from_secret(secret).unwrap();

        // Same secret should give same pubkey
        assert_eq!(signer1.node_pubkey(), signer2.node_pubkey());
    }

    #[test]
    fn test_cross_signer_verification() {
        let signer1 = MemorySigner::from_secret([1u8; 32]).unwrap();
        let signer2 = MemorySigner::from_secret([2u8; 32]).unwrap();

        let message = [42u8; 32];
        let signature = signer1.sign_schnorr(message).unwrap();

        // Signer2 can verify signer1's signature
        let pubkey1 = signer1.node_pubkey();
        assert!(signer2.verify_schnorr(&pubkey1, message, &signature));

        // But not with signer2's pubkey
        let pubkey2 = signer2.node_pubkey();
        assert!(!signer2.verify_schnorr(&pubkey2, message, &signature));
    }
}
