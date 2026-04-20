// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signing message construction for the Bitcoin Deposits protocol.
//!
//! This module contains pure data construction functions that build signing
//! messages without performing any cryptographic operations. Actual signing
//! and verification lives in `deposits_core::signing`.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

/// Get the withdrawal authorization message that should be signed.
///
/// The message format is: SHA256("WITHDRAWAL:{nonce}:{deposit_id}:{address}:{amount}:{fee}")
/// This can be used to create signatures that satisfy the withdrawal's descriptor.
pub fn withdrawal_signing_message(
    nonce: &[u8; 32],
    deposit_id: &crate::types::DepositId,
    destination_address: &str,
    amount_sats: u64,
    fee_sats: u64,
) -> [u8; 32] {
    use crate::types::OnChainWithdrawal;

    // Create the canonical signing message
    let signing_message = OnChainWithdrawal::signing_message(
        nonce,
        deposit_id,
        destination_address,
        amount_sats,
        fee_sats,
    );

    // Hash the message
    sha256::Hash::hash(signing_message.as_bytes()).to_byte_array()
}

/// Create the signing message hash for an invoice lock (Lightning payment).
///
/// Format: SHA256("INVOICE:{deposit_id}:{payment_hash}:{amount_with_fees}")
///
/// The depositor signs this message to authorize the custodian to deduct up to
/// `amount_with_fees` from their deposit when the payment preimage is revealed.
///
/// # Arguments
/// * `deposit_id` - The deposit being debited
/// * `payment_hash` - The Lightning payment hash (32 bytes)
/// * `amount_with_fees` - Maximum amount (in msats) the custodian can deduct
pub fn invoice_lock_signing_message(
    deposit_id: &crate::types::DepositId,
    payment_hash: &[u8; 32],
    amount_with_fees: u64,
) -> [u8; 32] {
    let message = format!(
        "INVOICE:{}:{}:{}",
        hex::encode(deposit_id),
        hex::encode(payment_hash),
        amount_with_fees
    );
    sha256::Hash::hash(message.as_bytes()).to_byte_array()
}

/// Create the signing message hash for a transfer lock.
///
/// Format: SHA256("TRANSFER:{nonce}:{source}:{dest}:{amount_msats}:{fee_msats}:{script}:{timeout}")
///
/// The source deposit holder signs this to authorize locking funds for conditional transfer.
/// All amounts are in millisatoshis.
pub fn transfer_lock_signing_message(
    nonce: &[u8; 32],
    source_deposit_id: &crate::types::DepositId,
    destination_deposit_id: &crate::types::DepositId,
    amount_msats: u64,
    fee_msats: u64,
    completion_script: &str,
    timeout_height: u32,
) -> [u8; 32] {
    let message = format!(
        "TRANSFER:{}:{}:{}:{}:{}:{}:{}",
        hex::encode(nonce),
        hex::encode(source_deposit_id),
        hex::encode(destination_deposit_id),
        amount_msats,
        fee_msats,
        completion_script,
        timeout_height
    );
    sha256::Hash::hash(message.as_bytes()).to_byte_array()
}

/// Compute the transfer_id from the signing message.
pub fn compute_transfer_id(signing_message: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::hash(signing_message).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::compute_deposit_id;

    #[test]
    fn test_transfer_lock_signing_message() {
        let nonce = [0x01u8; 32];
        let source_id = compute_deposit_id("pk(source)");
        let dest_id = compute_deposit_id("pk(dest)");
        let amount = 100_000u64;
        let fee = 1_000u64;
        let completion_script =
            "sha256(0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)";
        let timeout_height = 850_000u32;

        // Generate signing message
        let msg1 = transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );

        // Same inputs should produce same output
        let msg2 = transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );
        assert_eq!(
            msg1, msg2,
            "Same inputs should produce same signing message"
        );

        // Different nonce should produce different message
        let different_nonce = [0x02u8; 32];
        let msg3 = transfer_lock_signing_message(
            &different_nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );
        assert_ne!(
            msg1, msg3,
            "Different nonce should produce different message"
        );

        // Different amount should produce different message
        let msg4 = transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount + 1,
            fee,
            completion_script,
            timeout_height,
        );
        assert_ne!(
            msg1, msg4,
            "Different amount should produce different message"
        );

        // Different fee should produce different message
        let msg5 = transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount,
            fee + 1,
            completion_script,
            timeout_height,
        );
        assert_ne!(msg1, msg5, "Different fee should produce different message");
    }

    #[test]
    fn test_compute_transfer_id() {
        let nonce = [0x42u8; 32];
        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");
        let amount = 50_000u64;
        let fee = 500u64;
        let completion_script = "sha256(deadbeef)";
        let timeout_height = 900_000u32;

        let signing_msg = transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );

        let transfer_id = compute_transfer_id(&signing_msg);

        // transfer_id should be 32 bytes
        assert_eq!(transfer_id.len(), 32);

        // Same signing message should produce same transfer_id
        let transfer_id2 = compute_transfer_id(&signing_msg);
        assert_eq!(transfer_id, transfer_id2);

        // Different signing message should produce different transfer_id
        let different_nonce = [0x43u8; 32];
        let different_signing_msg = transfer_lock_signing_message(
            &different_nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );
        let different_transfer_id = compute_transfer_id(&different_signing_msg);
        assert_ne!(transfer_id, different_transfer_id);
    }
}
