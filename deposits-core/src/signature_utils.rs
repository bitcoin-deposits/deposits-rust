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

/// Verify a Schnorr signature proving ownership of a deposit's scriptpubkey
///
/// The signed message is: SHA256(pubkey || payment_id || amount)
/// This proves the deposit owner authorized this specific payment.
///
/// Returns true if the signature is valid, false otherwise.
/// Note: All-zero signatures are accepted during development (placeholder).
pub fn verify_payment_signature(
    pubkey: &PublicKey,
    payment_id: &[u8; 32],
    amount: u64,
    signature: &[u8; 64],
) -> bool {
    use bitcoin::secp256k1::schnorr::Signature;

    // Skip validation for placeholder signatures (all zeros) during development
    // TODO: Remove this bypass once wallet signing is implemented
    if signature.iter().all(|&b| b == 0) {
        return true;  // Accept placeholder signatures for now
    }

    // Build the message to verify
    let mut message_data = Vec::with_capacity(33 + 32 + 8);
    message_data.extend_from_slice(&pubkey.serialize());
    message_data.extend_from_slice(payment_id);
    message_data.extend_from_slice(&amount.to_le_bytes());

    let message_hash = sha256::Hash::hash(&message_data);
    let secp = Secp256k1::verification_only();

    // Parse the signature
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Get x-only pubkey for Schnorr verification
    let x_only = pubkey.x_only_public_key().0;
    let msg = Message::from_digest(message_hash.to_byte_array());

    secp.verify_schnorr(&sig, &msg, &x_only).is_ok()
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

/// Create a deposit offer signature (operator's commitment to credit deposit with on-chain funds)
///
/// The operator signs the offer parameters to commit to crediting the deposit
/// when funds are received at the specified address.
pub fn create_deposit_offer_signature(
    operator_secret: &SecretKey,
    operator_id: &PublicKey,
    reserves_id: &str,
    deposit_pubkey: &PublicKey,
    funding_address: &str,
    max_amount_sats: u64,
    min_amount_sats: u64,
    deadline_block: u32,
) -> Result<[u8; 64], DepositsError> {
    use crate::types::DepositOffer;

    // Create the canonical signing message
    let signing_message = DepositOffer::signing_message(
        operator_id,
        reserves_id,
        deposit_pubkey,
        funding_address,
        max_amount_sats,
        min_amount_sats,
        deadline_block,
    );

    // Hash the message
    let message_hash = sha256::Hash::hash(signing_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Sign the message
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&secp_message, operator_secret);

    Ok(signature.serialize_compact())
}

/// Verify a deposit offer signature
///
/// Verifies that the operator committed to the specified deposit offer parameters.
pub fn verify_deposit_offer_signature(
    offer: &crate::types::DepositOffer,
) -> Result<bool, DepositsError> {
    // Get the signing message
    let signing_message = offer.get_signing_message();

    // Hash the message
    let message_hash = sha256::Hash::hash(signing_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Parse signature
    let signature = Signature::from_compact(&offer.operator_signature)
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_signature".to_string(),
            details: "Failed to parse deposit offer signature".to_string(),
        })?;

    // Verify signature against operator's public key
    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&secp_message, &signature, &offer.operator_id) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a withdrawal authorization signature (depositor authorizes withdrawal)
///
/// The depositor signs the withdrawal parameters to authorize the operator
/// to send funds to the specified address. The nonce ensures uniqueness.
pub fn create_withdrawal_signature(
    depositor_secret: &SecretKey,
    nonce: &[u8; 32],
    deposit_pubkey: &PublicKey,
    destination_address: &str,
    amount_sats: u64,
    fee_sats: u64,
) -> Result<[u8; 64], DepositsError> {
    use crate::types::OnChainWithdrawal;

    // Create the canonical signing message
    let signing_message = OnChainWithdrawal::signing_message(
        nonce,
        deposit_pubkey,
        destination_address,
        amount_sats,
        fee_sats,
    );

    // Hash the message
    let message_hash = sha256::Hash::hash(signing_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Sign the message
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&secp_message, depositor_secret);

    Ok(signature.serialize_compact())
}

/// Verify a withdrawal authorization signature
///
/// Verifies that the depositor authorized the withdrawal to the specified address.
pub fn verify_withdrawal_signature(
    withdrawal: &crate::types::OnChainWithdrawal,
) -> Result<bool, DepositsError> {
    // Get the signing message
    let signing_message = withdrawal.get_signing_message();

    // Hash the message
    let message_hash = sha256::Hash::hash(signing_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref())
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        })?;

    // Parse signature
    let signature = Signature::from_compact(&withdrawal.depositor_signature)
        .map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_signature".to_string(),
            details: "Failed to parse withdrawal signature".to_string(),
        })?;

    // Verify signature against depositor's public key
    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&secp_message, &signature, &withdrawal.deposit_pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
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

    #[test]
    fn test_verify_payment_signature_placeholder() {
        let (_secret, public) = create_test_keypair();
        let payment_id = [1u8; 32];
        let amount = 1000u64;
        let placeholder_sig = [0u8; 64];

        // Placeholder signatures should be accepted during development
        assert!(verify_payment_signature(&public, &payment_id, amount, &placeholder_sig));
    }

    #[test]
    fn test_verify_payment_signature_invalid() {
        let (_secret, public) = create_test_keypair();
        let payment_id = [1u8; 32];
        let amount = 1000u64;
        let invalid_sig = [1u8; 64]; // Non-zero but invalid signature

        // Invalid signatures should be rejected
        assert!(!verify_payment_signature(&public, &payment_id, amount, &invalid_sig));
    }

    #[test]
    fn test_deposit_offer_signature_roundtrip() {
        use crate::types::DepositOffer;

        let (operator_secret, operator_pubkey) = create_test_keypair();

        // Create another keypair for partner
        let secp = Secp256k1::new();
        let partner_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let partner_pubkey = PublicKey::from_secret_key(&secp, &partner_secret);

        // And one for deposit
        let deposit_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

        let funding_address = "bc1qtest123456789";
        let max_amount_sats = 1_000_000u64;
        let min_amount_sats = 10_000u64;
        let deadline_block = 800_000u32;

        let partner_reserves_id = partner_pubkey.to_string();

        // Create signature
        let sig = create_deposit_offer_signature(
            &operator_secret,
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_pubkey,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        ).unwrap();

        // Create the offer struct
        let signing_message = DepositOffer::signing_message(
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_pubkey,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        let offer = DepositOffer {
            operator_id: operator_pubkey,
            reserves_id: partner_reserves_id.clone(),
            deposit_pubkey,
            funding_address: funding_address.to_string(),
            max_amount_sats,
            min_amount_sats,
            deadline_block,
            created_at_block: 799_000,
            offer_id,
            operator_signature: sig,
        };

        // Verify signature
        let valid = verify_deposit_offer_signature(&offer).unwrap();
        assert!(valid, "Deposit offer signature should be valid");
    }

    #[test]
    fn test_deposit_offer_signature_wrong_amount() {
        use crate::types::DepositOffer;

        let (operator_secret, operator_pubkey) = create_test_keypair();
        let secp = Secp256k1::new();
        let partner_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let partner_pubkey = PublicKey::from_secret_key(&secp, &partner_secret);
        let deposit_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

        let funding_address = "bc1qtest123456789";
        let max_amount_sats = 1_000_000u64;
        let min_amount_sats = 10_000u64;
        let deadline_block = 800_000u32;
        let partner_reserves_id = partner_pubkey.to_string();

        // Create signature with original amount
        let sig = create_deposit_offer_signature(
            &operator_secret,
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_pubkey,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        ).unwrap();

        // Create offer with different amount
        let signing_message = DepositOffer::signing_message(
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_pubkey,
            funding_address,
            max_amount_sats + 1000, // Different amount!
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        let offer = DepositOffer {
            operator_id: operator_pubkey,
            reserves_id: partner_reserves_id.clone(),
            deposit_pubkey,
            funding_address: funding_address.to_string(),
            max_amount_sats: max_amount_sats + 1000, // Different amount!
            min_amount_sats,
            deadline_block,
            created_at_block: 799_000,
            offer_id,
            operator_signature: sig, // Signed with original amount
        };

        // Verify should fail - signature doesn't match modified amount
        let valid = verify_deposit_offer_signature(&offer).unwrap();
        assert!(!valid, "Signature should be invalid for modified amount");
    }

    #[test]
    fn test_withdrawal_signature_roundtrip() {
        use crate::types::OnChainWithdrawal;

        let (depositor_secret, deposit_pubkey) = create_test_keypair();

        let nonce = [42u8; 32];
        let destination_address = "bc1qwithdrawal123456789";
        let amount_sats = 500_000u64;
        let fee_sats = 1_000u64;

        // Create signature
        let sig = create_withdrawal_signature(
            &depositor_secret,
            &nonce,
            &deposit_pubkey,
            destination_address,
            amount_sats,
            fee_sats,
        ).unwrap();

        // Create the withdrawal struct
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_pubkey,
            destination_address,
            amount_sats,
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_pubkey,
            destination_address: destination_address.to_string(),
            amount_sats,
            fee_sats,
            requested_at_block: 800_000,
            memo: Some("Test withdrawal".to_string()),
            depositor_signature: sig,
        };

        // Verify signature
        let valid = verify_withdrawal_signature(&withdrawal).unwrap();
        assert!(valid, "Withdrawal signature should be valid");

        // Verify OP_RETURN data
        let op_return = withdrawal.op_return_data();
        assert_eq!(&op_return[0..5], b"WDRL:");
        assert_eq!(&op_return[5..33], &withdrawal_id[..28]);
        assert!(withdrawal.verify_op_return(&op_return));
    }

    #[test]
    fn test_withdrawal_signature_wrong_amount() {
        use crate::types::OnChainWithdrawal;

        let (depositor_secret, deposit_pubkey) = create_test_keypair();

        let nonce = [42u8; 32];
        let destination_address = "bc1qwithdrawal123456789";
        let amount_sats = 500_000u64;
        let fee_sats = 1_000u64;

        // Create signature with original amount
        let sig = create_withdrawal_signature(
            &depositor_secret,
            &nonce,
            &deposit_pubkey,
            destination_address,
            amount_sats,
            fee_sats,
        ).unwrap();

        // Create withdrawal with different amount
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_pubkey,
            destination_address,
            amount_sats + 1000, // Different amount!
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_pubkey,
            destination_address: destination_address.to_string(),
            amount_sats: amount_sats + 1000, // Different amount!
            fee_sats,
            requested_at_block: 800_000,
            memo: None,
            depositor_signature: sig, // Signed with original amount
        };

        // Verify should fail - signature doesn't match modified amount
        let valid = verify_withdrawal_signature(&withdrawal).unwrap();
        assert!(!valid, "Signature should be invalid for modified amount");
    }
}
