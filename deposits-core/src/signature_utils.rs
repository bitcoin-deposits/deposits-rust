// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signature utilities for the Bitcoin Deposits protocol.
//!
//! This module contains functions for creating and verifying various signatures
//! used in the deposits protocol, including deposit guarantees and payment authorizations.

use bitcoin::secp256k1::{Message, PublicKey, SecretKey, Secp256k1, ecdsa::Signature};
use bitcoin::hashes::{Hash, sha256};
use crate::error::DepositsError;

/// Create a deposit guarantee signature (Bob's commitment to credit specific deposit)
/// Bob's private key signs: "DEPOSIT_GUARANTEE:{invoice}:{deposit_pubkey}"
/// This allows Charlie to verify that paying the invoice will credit his specific deposit
pub fn create_deposit_guarantee_signature(
    private_key: &SecretKey,
    invoice: &str,
    deposit_pubkey: &PublicKey
) -> Result<[u8; 64], DepositsError> {
    // Create the guarantee message that Bob signs
    // Format: "DEPOSIT_GUARANTEE:{invoice}:{deposit_pubkey}"
    let guarantee_message = format!("DEPOSIT_GUARANTEE:{}:{}", invoice, deposit_pubkey);

    // Hash the message
    let message_hash = sha256::Hash::hash(guarantee_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Sign the message
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&secp_message, private_key);

    Ok(signature.serialize_compact())
}

/// Verify a deposit guarantee signature
/// Verifies that Bob committed to crediting the specified deposit when the invoice is paid
pub fn verify_deposit_guarantee_signature(
    signature: &[u8; 64],
    bob_pubkey: &PublicKey,
    invoice: &str,
    deposit_pubkey: &PublicKey
) -> Result<bool, DepositsError> {
    // Recreate the same guarantee message Bob signed
    let guarantee_message = format!("DEPOSIT_GUARANTEE:{}:{}", invoice, deposit_pubkey);

    // Hash the message
    let message_hash = sha256::Hash::hash(guarantee_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Parse signature
    let signature = Signature::from_compact(signature)
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_signature".to_string(),
            details: "Failed to parse signature".to_string(),
        })?;

    // Verify signature
    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&secp_message, &signature, bob_pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a payment authorization signature (for testing and wallet integration)
/// The deposit owner's private key signs: "PAY:{amount}:{invoice}:{preimage_hex}"
pub fn create_payment_authorization_signature(
    private_key: &SecretKey,
    amount: u64,
    invoice_to_pay: &str,
    payment_preimage: &[u8; 32]
) -> Result<Vec<u8>, DepositsError> {
    // Create the message that should be signed
    // Format: "PAY:{amount}:{invoice}:{preimage_hex}"
    let preimage_hex = hex::encode(payment_preimage);
    let authorization_message = format!("PAY:{}:{}:{}", amount, invoice_to_pay, preimage_hex);

    // Hash the message
    let message_hash = sha256::Hash::hash(authorization_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Sign the message
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&secp_message, private_key);

    Ok(signature.serialize_compact().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    fn create_test_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret);
        (secret, public)
    }

    #[test]
    fn test_deposit_guarantee_roundtrip() {
        let (secret, public) = create_test_keypair();
        let invoice = "lnbc1000n1ptest";
        let deposit_pubkey = public; // Use same key for simplicity

        // Create signature
        let sig = create_deposit_guarantee_signature(&secret, invoice, &deposit_pubkey).unwrap();

        // Verify signature
        let valid = verify_deposit_guarantee_signature(&sig, &public, invoice, &deposit_pubkey).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deposit_guarantee_wrong_invoice() {
        let (secret, public) = create_test_keypair();
        let invoice = "lnbc1000n1ptest";
        let wrong_invoice = "lnbc2000n1ptest";
        let deposit_pubkey = public;

        // Create signature with original invoice
        let sig = create_deposit_guarantee_signature(&secret, invoice, &deposit_pubkey).unwrap();

        // Verify with wrong invoice should fail
        let valid = verify_deposit_guarantee_signature(&sig, &public, wrong_invoice, &deposit_pubkey).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_payment_authorization() {
        let (secret, _public) = create_test_keypair();
        let amount = 1000u64;
        let invoice = "lnbc1000n1ptest";
        let preimage = [42u8; 32];

        // Should successfully create authorization signature
        let sig = create_payment_authorization_signature(&secret, amount, invoice, &preimage).unwrap();
        assert_eq!(sig.len(), 64);
    }
}
