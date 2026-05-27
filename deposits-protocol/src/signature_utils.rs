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
