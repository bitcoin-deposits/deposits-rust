// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Cryptographic signing and verification for the Bitcoin Deposits protocol.
//!
//! This module contains all functions that perform actual crypto operations
//! (signing and verification). Pure data construction functions (signing message
//! builders) live in `deposits_protocol::signature_utils`.

use crate::error::DepositsError;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_protocol::signature_utils::{
    compute_transfer_id, invoice_lock_signing_message, transfer_lock_signing_message,
    withdrawal_signing_message,
};

/// Create a deposit guarantee signature (Bob's commitment to credit specific deposit)
/// Bob's private key signs: "DEPOSIT_GUARANTEE:{invoice}:{deposit_pubkey}"
/// This allows Charlie to verify that paying the invoice will credit his specific deposit
pub fn create_deposit_guarantee_signature(
    private_key: &SecretKey,
    invoice: &str,
    deposit_pubkey: &PublicKey,
) -> Result<[u8; 64], DepositsError> {
    // Create the guarantee message that Bob signs
    // Format: "DEPOSIT_GUARANTEE:{invoice}:{deposit_pubkey}"
    let guarantee_message = format!("DEPOSIT_GUARANTEE:{}:{}", invoice, deposit_pubkey);

    // Hash the message
    let message_hash = sha256::Hash::hash(guarantee_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref()).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        }
    })?;

    // Sign the message with Schnorr (BIP-340)
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, private_key);
    let signature = secp.sign_schnorr_no_aux_rand(&secp_message, &keypair);

    Ok(signature.serialize())
}

/// Verify a deposit guarantee signature
/// Verifies that Bob committed to crediting the specified deposit when the invoice is paid
pub fn verify_deposit_guarantee_signature(
    signature: &[u8; 64],
    bob_pubkey: &PublicKey,
    invoice: &str,
    deposit_pubkey: &PublicKey,
) -> Result<bool, DepositsError> {
    // Recreate the same guarantee message Bob signed
    let guarantee_message = format!("DEPOSIT_GUARANTEE:{}:{}", invoice, deposit_pubkey);

    // Hash the message
    let message_hash = sha256::Hash::hash(guarantee_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref()).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        }
    })?;

    // Parse signature
    let signature =
        Signature::from_slice(signature).map_err(|_| DepositsError::ProtocolViolation {
            violation_type: "invalid_signature".to_string(),
            details: "Failed to parse signature".to_string(),
        })?;

    // Verify Schnorr signature
    let secp = Secp256k1::verification_only();
    let (xonly, _parity) = bob_pubkey.x_only_public_key();
    match secp.verify_schnorr(&signature, &secp_message, &xonly) {
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
pub fn verify_payment_signature(
    pubkey: &PublicKey,
    payment_id: &[u8; 32],
    amount: u64,
    signature: &[u8; 64],
) -> bool {
    use bitcoin::secp256k1::schnorr::Signature;

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

/// Create a payment signature for invoice lock/fulfill operations
///
/// The signed message is: SHA256(pubkey || payment_id || amount)
/// This proves the deposit owner authorized this specific payment.
///
/// Returns the 64-byte Schnorr signature.
pub fn create_payment_signature(
    secret_key: &SecretKey,
    payment_id: &[u8; 32],
    amount: u64,
) -> Result<[u8; 64], DepositsError> {
    use bitcoin::secp256k1::schnorr::Signature;
    use bitcoin::secp256k1::Keypair;

    let secp = Secp256k1::new();

    // Derive the public key
    let pubkey = PublicKey::from_secret_key(&secp, secret_key);

    // Build the message to sign
    let mut message_data = Vec::with_capacity(33 + 32 + 8);
    message_data.extend_from_slice(&pubkey.serialize());
    message_data.extend_from_slice(payment_id);
    message_data.extend_from_slice(&amount.to_le_bytes());

    let message_hash = sha256::Hash::hash(&message_data);
    let msg = Message::from_digest(message_hash.to_byte_array());

    // Create keypair for Schnorr signing
    let keypair = Keypair::from_secret_key(&secp, secret_key);

    // Sign with Schnorr (no aux rand for deterministic signing)
    let sig: Signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    Ok(sig.serialize())
}

/// Create a payment authorization signature (for testing and wallet integration)
/// The deposit owner's private key signs: "PAY:{amount}:{invoice}:{preimage_hex}"
pub fn create_payment_authorization_signature(
    private_key: &SecretKey,
    amount: u64,
    invoice_to_pay: &str,
    payment_preimage: &[u8; 32],
) -> Result<Vec<u8>, DepositsError> {
    // Create the message that should be signed
    // Format: "PAY:{amount}:{invoice}:{preimage_hex}"
    let preimage_hex = hex::encode(payment_preimage);
    let authorization_message = format!("PAY:{}:{}:{}", amount, invoice_to_pay, preimage_hex);

    // Hash the message
    let message_hash = sha256::Hash::hash(authorization_message.as_bytes());
    let secp_message = Message::from_digest_slice(message_hash.as_ref()).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        }
    })?;

    // Sign the message with Schnorr (BIP-340)
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, private_key);
    let signature = secp.sign_schnorr_no_aux_rand(&secp_message, &keypair);

    Ok(signature.serialize().to_vec())
}

/// Create a deposit offer signature (operator's commitment to credit deposit with on-chain funds)
///
/// The operator signs the offer parameters to commit to crediting the deposit
/// when funds are received at the specified address.
pub fn create_deposit_offer_signature(
    operator_secret: &SecretKey,
    operator_id: &PublicKey,
    ledger_id: &str,
    deposit_id: &crate::types::DepositId,
    funding_address: &str,
    max_amount_sats: u64,
    min_amount_sats: u64,
    deadline_block: u32,
) -> Result<[u8; 64], DepositsError> {
    let message_hash = deposit_offer_signing_digest(
        operator_id,
        ledger_id,
        deposit_id,
        funding_address,
        max_amount_sats,
        min_amount_sats,
        deadline_block,
    );

    let secp_message = Message::from_digest(message_hash);

    // Sign the message with Schnorr (BIP-340)
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, operator_secret);
    let signature = secp.sign_schnorr_no_aux_rand(&secp_message, &keypair);

    Ok(signature.serialize())
}

/// Build the 32-byte digest a deposit-offer signature commits to.
///
/// Splitting the digest construction out of [`create_deposit_offer_signature`]
/// lets daemon-path callers feed the digest into a `Signer` (e.g. the
/// remote-signer abstraction in `deposits-signer-api`) instead of reaching
/// for the raw operator secret.
pub fn deposit_offer_signing_digest(
    operator_id: &PublicKey,
    ledger_id: &str,
    deposit_id: &crate::types::DepositId,
    funding_address: &str,
    max_amount_sats: u64,
    min_amount_sats: u64,
    deadline_block: u32,
) -> [u8; 32] {
    use crate::types::DepositOffer;
    let signing_message = DepositOffer::signing_message(
        operator_id,
        ledger_id,
        deposit_id,
        funding_address,
        max_amount_sats,
        min_amount_sats,
        deadline_block,
    );
    sha256::Hash::hash(signing_message.as_bytes()).to_byte_array()
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
    let secp_message = Message::from_digest_slice(message_hash.as_ref()).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_message_hash".to_string(),
            details: "Failed to create secp256k1 message from hash".to_string(),
        }
    })?;

    // Parse Schnorr signature
    let signature = Signature::from_slice(&offer.operator_signature).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_signature".to_string(),
            details: "Failed to parse deposit offer signature".to_string(),
        }
    })?;

    // Verify Schnorr signature against operator's x-only public key
    let secp = Secp256k1::verification_only();
    let (xonly, _parity) = offer.operator_id.x_only_public_key();
    match secp.verify_schnorr(&signature, &secp_message, &xonly) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a withdrawal authorization witness
///
/// Verifies that the witness satisfies the deposit descriptor for the withdrawal.
/// This delegates to `crate::descriptor::verify_witness` for actual verification.
pub fn verify_withdrawal_witness(
    withdrawal: &crate::types::OnChainWithdrawal,
    descriptor: &str,
    _block_height: u32,
) -> Result<bool, DepositsError> {
    // Get the signing message hash
    let message_hash = withdrawal_signing_message(
        &withdrawal.nonce,
        &withdrawal.deposit_id,
        &withdrawal.destination_address,
        withdrawal.amount_sats,
        withdrawal.fee_sats,
    );

    // Verify the witness satisfies the descriptor
    crate::descriptor::verify_witness(descriptor, &withdrawal.depositor_witness, &message_hash)
}

/// Verify an invoice lock witness satisfies the deposit descriptor.
///
/// Verifies that the witness authorizes the Lightning payment by checking
/// the signature against the descriptor and the invoice lock signing message.
pub fn verify_invoice_lock_witness(
    descriptor: &str,
    deposit_id: &crate::types::DepositId,
    payment_hash: &[u8; 32],
    amount_with_fees: u64,
    witness: &crate::types::DescriptorWitness,
) -> Result<bool, DepositsError> {
    let message_hash = invoice_lock_signing_message(deposit_id, payment_hash, amount_with_fees);
    crate::descriptor::verify_witness(descriptor, witness, &message_hash)
}

/// Verify a witness satisfies the source deposit's descriptor for a transfer lock.
///
/// This verifies that the witness authorizes locking funds from the source deposit
/// for a conditional transfer.
pub fn verify_transfer_lock_witness(
    source_descriptor: &str,
    source_deposit_id: &crate::types::DepositId,
    destination_deposit_id: &crate::types::DepositId,
    nonce: &[u8; 32],
    amount: u64,
    fee: u64,
    completion_script: &str,
    timeout_height: u32,
    witness: &crate::types::DescriptorWitness,
) -> Result<bool, DepositsError> {
    let message_hash = transfer_lock_signing_message(
        nonce,
        source_deposit_id,
        destination_deposit_id,
        amount,
        fee,
        completion_script,
        timeout_height,
    );
    crate::descriptor::verify_witness(source_descriptor, witness, &message_hash)
}

/// Verify a witness satisfies the completion_script for a transfer completion.
///
/// This verifies that the witness satisfies the completion condition (e.g., revealing
/// a preimage for sha256(H) or providing a valid signature for pk(X)).
pub fn verify_transfer_complete_witness(
    completion_script: &str,
    transfer_id: &[u8; 32],
    nonce: &[u8; 32],
    source_deposit_id: &crate::types::DepositId,
    destination_deposit_id: &crate::types::DepositId,
    amount: u64,
    fee: u64,
    timeout_height: u32,
    script_witness: &crate::types::DescriptorWitness,
) -> Result<bool, DepositsError> {
    // The signing message is the same as for the lock - both parties commit to same terms
    let message_hash = transfer_lock_signing_message(
        nonce,
        source_deposit_id,
        destination_deposit_id,
        amount,
        fee,
        completion_script,
        timeout_height,
    );

    // Verify the computed transfer_id matches
    let computed_id = compute_transfer_id(&message_hash);
    if computed_id != *transfer_id {
        return Err(DepositsError::InvalidSignature);
    }

    // Verify the witness satisfies the completion_script
    crate::descriptor::verify_witness(completion_script, script_witness, &message_hash)
}

/// Create a withdrawal authorization signature.
///
/// Creates a Schnorr signature authorizing a withdrawal from a deposit.
/// This signature is used as part of the DescriptorWitness for the withdrawal.
///
/// # Arguments
/// * `secret_key` - The deposit holder's secret key
/// * `nonce` - Unique nonce for the withdrawal request
/// * `deposit_pubkey` - The deposit's public key (for deriving deposit_id)
/// * `destination_address` - Address to withdraw to
/// * `amount_sats` - Amount to withdraw in satoshis
/// * `fee_sats` - Transaction fee in satoshis
///
/// # Returns
/// A 64-byte Schnorr signature
pub fn create_withdrawal_signature(
    secret_key: &SecretKey,
    nonce: &[u8; 32],
    deposit_pubkey: &PublicKey,
    destination_address: &str,
    amount_sats: u64,
    fee_sats: u64,
) -> Result<[u8; 64], DepositsError> {
    use bitcoin::secp256k1::schnorr::Signature;
    use bitcoin::secp256k1::Keypair;

    // Derive deposit_id from pubkey (for backwards compatibility)
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);

    // Get the message hash
    let message_hash = withdrawal_signing_message(
        nonce,
        &deposit_id,
        destination_address,
        amount_sats,
        fee_sats,
    );

    // Sign with Schnorr
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let msg = Message::from_digest(message_hash);
    let sig: Signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    Ok(sig.serialize())
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
        let valid =
            verify_deposit_guarantee_signature(&sig, &public, invoice, &deposit_pubkey).unwrap();
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
        let valid =
            verify_deposit_guarantee_signature(&sig, &public, wrong_invoice, &deposit_pubkey)
                .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_payment_authorization() {
        let (secret, _public) = create_test_keypair();
        let amount = 1000u64;
        let invoice = "lnbc1000n1ptest";
        let preimage = [42u8; 32];

        // Should successfully create authorization signature
        let sig =
            create_payment_authorization_signature(&secret, amount, invoice, &preimage).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_verify_payment_signature_zero_rejected() {
        // The all-zero signature used to be accepted as a development
        // placeholder (see commit history). It MUST now be rejected
        // like any other forged signature — without this, anyone could
        // forge `PaymentLock` / `PaymentFulfill` operations against any
        // deposit by sending 64 zero bytes as the witness.
        let (_secret, public) = create_test_keypair();
        let payment_id = [1u8; 32];
        let amount = 1000u64;
        let placeholder_sig = [0u8; 64];

        assert!(!verify_payment_signature(
            &public,
            &payment_id,
            amount,
            &placeholder_sig
        ));
    }

    #[test]
    fn test_verify_payment_signature_invalid() {
        let (_secret, public) = create_test_keypair();
        let payment_id = [1u8; 32];
        let amount = 1000u64;
        let invalid_sig = [1u8; 64]; // Non-zero but invalid signature

        // Invalid signatures should be rejected
        assert!(!verify_payment_signature(
            &public,
            &payment_id,
            amount,
            &invalid_sig
        ));
    }

    #[test]
    fn test_deposit_offer_signature_roundtrip() {
        use crate::types::{compute_deposit_id, DepositOffer};

        let (operator_secret, operator_pubkey) = create_test_keypair();

        // Create another keypair for partner
        let secp = Secp256k1::new();
        let partner_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let partner_pubkey = PublicKey::from_secret_key(&secp, &partner_secret);

        // And one for deposit - create descriptor and compute deposit_id
        let deposit_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

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
            &deposit_id,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        )
        .unwrap();

        // Create the offer struct
        let signing_message = DepositOffer::signing_message(
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_id,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        let offer = DepositOffer {
            operator_id: operator_pubkey,
            ledger_id: partner_reserves_id.clone(),
            deposit_id,
            descriptor,
            funding_address: funding_address.to_string(),
            max_amount_sats,
            min_amount_sats,
            deadline_block,
            created_at_block: 799_000,
            offer_id,
            operator_signature: sig,
            fees: None,
            transfer_fees: None,
        };

        // Verify signature
        let valid = verify_deposit_offer_signature(&offer).unwrap();
        assert!(valid, "Deposit offer signature should be valid");
    }

    #[test]
    fn test_deposit_offer_signature_wrong_amount() {
        use crate::types::{compute_deposit_id, DepositOffer};

        let (operator_secret, operator_pubkey) = create_test_keypair();
        let secp = Secp256k1::new();
        let partner_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let partner_pubkey = PublicKey::from_secret_key(&secp, &partner_secret);
        let deposit_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

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
            &deposit_id,
            funding_address,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        )
        .unwrap();

        // Create offer with different amount
        let signing_message = DepositOffer::signing_message(
            &operator_pubkey,
            &partner_reserves_id,
            &deposit_id,
            funding_address,
            max_amount_sats + 1000, // Different amount!
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        let offer = DepositOffer {
            operator_id: operator_pubkey,
            ledger_id: partner_reserves_id.clone(),
            deposit_id,
            descriptor,
            funding_address: funding_address.to_string(),
            max_amount_sats: max_amount_sats + 1000, // Different amount!
            min_amount_sats,
            deadline_block,
            created_at_block: 799_000,
            offer_id,
            operator_signature: sig, // Signed with original amount
            fees: None,
            transfer_fees: None,
        };

        // Verify should fail - signature doesn't match modified amount
        let valid = verify_deposit_offer_signature(&offer).unwrap();
        assert!(!valid, "Signature should be invalid for modified amount");
    }

    #[test]
    fn test_withdrawal_signature_roundtrip() {
        use crate::types::{compute_deposit_id, DescriptorWitness, OnChainWithdrawal};

        let (depositor_secret, deposit_pubkey) = create_test_keypair();
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

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
        )
        .unwrap();

        // Create the withdrawal struct
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_id,
            destination_address,
            amount_sats,
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_id,
            destination_address: destination_address.to_string(),
            amount_sats,
            fee_sats,
            requested_at_block: 800_000,
            memo: Some("Test withdrawal".to_string()),
            depositor_witness: DescriptorWitness::from_signature(&sig),
        };

        // Verify signature using verify_withdrawal_witness
        let valid = verify_withdrawal_witness(&withdrawal, &descriptor, 800_000).unwrap();
        assert!(valid, "Withdrawal signature should be valid");

        // Verify OP_RETURN data
        let op_return = withdrawal.op_return_data();
        assert_eq!(&op_return[0..5], b"WDRL:");
        assert_eq!(&op_return[5..33], &withdrawal_id[..28]);
        assert!(withdrawal.verify_op_return(&op_return));
    }

    #[test]
    fn test_withdrawal_signature_wrong_amount() {
        use crate::types::{compute_deposit_id, DescriptorWitness, OnChainWithdrawal};

        let (depositor_secret, deposit_pubkey) = create_test_keypair();
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

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
        )
        .unwrap();

        // Create withdrawal with different amount
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_id,
            destination_address,
            amount_sats + 1000, // Different amount!
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_id,
            destination_address: destination_address.to_string(),
            amount_sats: amount_sats + 1000, // Different amount!
            fee_sats,
            requested_at_block: 800_000,
            memo: None,
            depositor_witness: DescriptorWitness::from_signature(&sig), // Signed with original amount
        };

        // Verify should fail - signature doesn't match modified amount
        let valid = verify_withdrawal_witness(&withdrawal, &descriptor, 800_000).unwrap();
        assert!(!valid, "Signature should be invalid for modified amount");
    }
}
