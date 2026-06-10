// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signing message construction for the Bitcoin Deposits protocol.
//!
//! Authorization on signature-bearing `LedgerOperation`s is now signed over the
//! dep-17 operation preimage (see `deposits_core::dep16::operations::operation_sighash`
//! and the `sign_op` helper in `deposits_core::signing`). Per-op signing helpers
//! used to live here (`invoice_lock_signing_message`, `withdrawal_signing_message`,
//! `transfer_lock_signing_message`) but their domains are subsumed by the dep-17
//! preimage and have been removed.
//!
//! What's left here is signing-message construction for protocol artifacts that
//! AREN'T per-op authorizations — cosignatures on invoices and deposit offers,
//! which sign over their own canonical messages.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

/// Build the message a quorum member signs when co-signing an invoice.
///
/// Format: BIP-340 tagged hash with tag `deposits/invoice_cosign` over
/// `ledger_id_bytes || payment_hash || deposit_id || amount_msat (LE)
///   || cosigner_ledger_hash`. The cosigner commits to both the invoice
/// terms and their own ledger state at the moment they cosigned, which
/// is what makes the cosignature meaningful for fraud claims later.
pub fn invoice_cosign_signing_message(
    ledger_id: &str,
    payment_hash: &[u8; 32],
    deposit_id: &crate::types::DepositId,
    amount_msat: u64,
    cosigner_ledger_hash: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(ledger_id.as_bytes());
    data.extend_from_slice(payment_hash);
    data.extend_from_slice(deposit_id);
    data.extend_from_slice(&amount_msat.to_le_bytes());

    let tag = b"deposits/invoice_cosign";
    let tag_hash = sha256::Hash::hash(tag);
    let mut tagged = Vec::with_capacity(64 + data.len() + 32);
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(&data);
    tagged.extend_from_slice(cosigner_ledger_hash);
    sha256::Hash::hash(&tagged).to_byte_array()
}

/// Build the message a quorum member signs when co-signing a deposit
/// offer. Format must match what producers (operator-side cosign
/// handler, wallet-side `verify_offer_cosignature`) construct:
///
/// BIP-340 tagged hash with tag `deposits/offer_cosign` over
/// `ledger_id_bytes || offer_id || operator_id.serialize()[1..]
///   || u8(addr_len) || funding_address || u32_le(deadline_block)
///   || cosigner_ledger_hash`.
pub fn offer_cosign_signing_message(
    ledger_id: &str,
    offer_id: &[u8; 32],
    operator_id: &PublicKey,
    funding_address: &str,
    deadline_block: u32,
    cosigner_ledger_hash: &[u8; 32],
) -> [u8; 32] {
    let addr_bytes = funding_address.as_bytes();
    let mut data = Vec::with_capacity(32 + 32 + 32 + 1 + addr_bytes.len() + 4);
    data.extend_from_slice(ledger_id.as_bytes());
    data.extend_from_slice(offer_id);
    data.extend_from_slice(&operator_id.serialize()[1..]); // x-only
    data.push(addr_bytes.len() as u8);
    data.extend_from_slice(addr_bytes);
    data.extend_from_slice(&deadline_block.to_le_bytes());

    let tag = b"deposits/offer_cosign";
    let tag_hash = sha256::Hash::hash(tag);
    let mut tagged = Vec::with_capacity(64 + data.len() + 32);
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(&data);
    tagged.extend_from_slice(cosigner_ledger_hash);
    sha256::Hash::hash(&tagged).to_byte_array()
}

/// Build the 32-byte digest a wallet signs to pre-authorize a settlement-
/// atomic `InvoiceCredit` (DEP-07 §"Tiered receive"). The wallet signs this
/// digest with the deposit-authorization key; the operator stores the
/// signature and embeds it in `InvoiceCredit.wallet_authorization` when
/// the payment arrives.
///
/// Format: BIP-340 tagged hash with tag `deposits/invoice_credit_auth` over
/// `deposit_id || payment_hash || amount_msat (LE)`.
///
/// `sequence_number` and `invoice_id` are intentionally NOT in the digest:
/// the operator picks the sequence at commit time, and the invoice_id is
/// derived from the payment_hash. The wallet's authorization commits to
/// *what gets credited*, not *when* — so the operator can commit at any
/// sequence as long as the credit terms match.
pub fn invoice_credit_auth_signing_message(
    deposit_id: &crate::types::DepositId,
    payment_hash: &[u8; 32],
    amount_msat: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(16 + 32 + 8);
    data.extend_from_slice(deposit_id);
    data.extend_from_slice(payment_hash);
    data.extend_from_slice(&amount_msat.to_le_bytes());

    let tag = b"deposits/invoice_credit_auth";
    let tag_hash = sha256::Hash::hash(tag);
    let mut tagged = Vec::with_capacity(64 + data.len());
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(tag_hash.as_byte_array());
    tagged.extend_from_slice(&data);
    sha256::Hash::hash(&tagged).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DepositId;

    /// The signing-message digest is deterministic: same inputs → same bytes.
    #[test]
    fn invoice_credit_auth_digest_is_deterministic() {
        let deposit_id: DepositId = [0x11; 16];
        let payment_hash = [0x22u8; 32];
        let amount = 12_345_678u64;
        let a = invoice_credit_auth_signing_message(&deposit_id, &payment_hash, amount);
        let b = invoice_credit_auth_signing_message(&deposit_id, &payment_hash, amount);
        assert_eq!(a, b);
    }

    /// Each input field affects the digest — no field can be silently
    /// swapped at commit time without invalidating the wallet's signature.
    #[test]
    fn invoice_credit_auth_digest_changes_with_each_input() {
        let deposit_id: DepositId = [0x11; 16];
        let payment_hash = [0x22u8; 32];
        let amount = 12_345_678u64;
        let base = invoice_credit_auth_signing_message(&deposit_id, &payment_hash, amount);

        // Different deposit_id → different digest.
        let mut other_id = deposit_id;
        other_id[0] ^= 0x01;
        assert_ne!(
            base,
            invoice_credit_auth_signing_message(&other_id, &payment_hash, amount)
        );

        // Different payment_hash → different digest.
        let mut other_hash = payment_hash;
        other_hash[0] ^= 0x01;
        assert_ne!(
            base,
            invoice_credit_auth_signing_message(&deposit_id, &other_hash, amount)
        );

        // Different amount → different digest.
        assert_ne!(
            base,
            invoice_credit_auth_signing_message(&deposit_id, &payment_hash, amount + 1)
        );
    }

    /// Domain-separation: the same `(deposit_id, payment_hash, amount_msat)`
    /// triple under a different tag yields a different digest. This is the
    /// safety property tagged hashes exist to provide — an attacker can't
    /// reuse a signature meant for one purpose to authorize another.
    #[test]
    fn invoice_credit_auth_is_domain_separated_from_invoice_cosign() {
        let deposit_id: DepositId = [0x11; 16];
        let payment_hash = [0x22u8; 32];
        let amount = 1000u64;
        let auth = invoice_credit_auth_signing_message(&deposit_id, &payment_hash, amount);
        let cosign = invoice_cosign_signing_message(
            "ledger_id_string",
            &payment_hash,
            &deposit_id,
            amount,
            &[0u8; 32], // cosigner_ledger_hash
        );
        assert_ne!(auth, cosign);
    }
}
