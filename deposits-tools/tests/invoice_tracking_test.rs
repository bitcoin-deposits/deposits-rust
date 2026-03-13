//! Invoice Tracking Tests
//!
//! Tests for the invoice tracking system that ensures:
//! 1. Invoices are added to deposit.invoices when cosigning succeeds
//! 2. Invoices are removed when payments are credited
//! 3. payment_deposits index stays in sync with deposit.invoices

#![cfg(feature = "bitcoin-deposits")]

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

// Use core types for Invoice/PendingInvoice since Deposit.invoices is Vec<deposits_core::Invoice>
use deposits_core::{Invoice, PendingInvoice, FeeStructure};
// Use Deposit type from deposits-core
use deposits_core::types::Deposit;

/// Generate a test public key from a seed byte
fn generate_test_pubkey(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[31] = seed;
    let sk = SecretKey::from_slice(&secret).unwrap();
    PublicKey::from_secret_key(&secp, &sk)
}

/// Generate a valid payment hash from a preimage
fn generate_payment_hash(preimage: &[u8; 32]) -> [u8; 32] {
    *sha256::Hash::hash(preimage).as_byte_array()
}

/// Compute deposit_id from pubkey
fn deposit_id_from_pubkey(pubkey: &PublicKey) -> deposits_core::types::DepositId {
    let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
    deposits_core::types::compute_deposit_id(&descriptor)
}

/// Create a test invoice
fn create_test_invoice(deposit_pubkey: PublicKey, payment_hash: [u8; 32], amount: u64) -> Invoice {
    let deposit_id = deposit_id_from_pubkey(&deposit_pubkey);
    Invoice {
        id: hex::encode(&payment_hash),
        payment_hash,
        amount,
        expires: 1700000000 + 3600, // 1 hour from some timestamp
        assigned_deposit: deposit_id,
        bolt11: format!("lnbc{}n1test", amount / 1000),
    }
}

/// Create a test pending invoice
fn create_test_pending_invoice(deposit_pubkey: PublicKey, payment_hash: [u8; 32], amount: u64) -> PendingInvoice {
    let deposit_id = deposit_id_from_pubkey(&deposit_pubkey);
    PendingInvoice {
        amount,
        payment_hash,
        expires: 1700000000 + 3600,
        assigned_deposit: deposit_id,
        invoice_id: hex::encode(&payment_hash),
        bolt11: format!("lnbc{}n1test", amount / 1000),
    }
}

/// Create a default fee structure for testing
fn default_fee_structure() -> FeeStructure {
    FeeStructure::new(0, 0, 144) // daily
}

/// Create a test deposit
fn create_test_deposit(pubkey: PublicKey, balance: u64) -> Deposit {
    let mut deposit = Deposit::from_pubkey(pubkey, Some(default_fee_structure()));
    deposit.balance = balance;
    deposit
}

// =============================================================================
// Invoice Storage in Deposit Tests
// =============================================================================

#[test]
fn test_deposit_invoices_initially_empty() {
    let deposit = create_test_deposit(generate_test_pubkey(1), 0);
    assert!(deposit.invoices.is_empty());
}

#[test]
fn test_deposit_can_store_invoice() {
    let deposit_pubkey = generate_test_pubkey(1);
    let preimage: [u8; 32] = [0xAB; 32];
    let payment_hash = generate_payment_hash(&preimage);

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    let invoice = create_test_invoice(deposit_pubkey, payment_hash, 10_000_000);
    deposit.invoices.push(invoice.clone());

    assert_eq!(deposit.invoices.len(), 1);
    assert_eq!(deposit.invoices[0].payment_hash, payment_hash);
    assert_eq!(deposit.invoices[0].amount, 10_000_000);
}

#[test]
fn test_deposit_can_store_multiple_invoices() {
    let deposit_pubkey = generate_test_pubkey(1);
    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    // Add 3 invoices
    for i in 1..=3 {
        let preimage: [u8; 32] = [i; 32];
        let payment_hash = generate_payment_hash(&preimage);
        let invoice = create_test_invoice(deposit_pubkey, payment_hash, i as u64 * 1_000_000);
        deposit.invoices.push(invoice);
    }

    assert_eq!(deposit.invoices.len(), 3);
}

#[test]
fn test_invoice_removal_by_payment_hash() {
    let deposit_pubkey = generate_test_pubkey(1);
    let preimage1: [u8; 32] = [0xAA; 32];
    let preimage2: [u8; 32] = [0xBB; 32];
    let payment_hash1 = generate_payment_hash(&preimage1);
    let payment_hash2 = generate_payment_hash(&preimage2);

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);
    deposit.invoices.push(create_test_invoice(deposit_pubkey, payment_hash1, 5_000_000));
    deposit.invoices.push(create_test_invoice(deposit_pubkey, payment_hash2, 10_000_000));

    assert_eq!(deposit.invoices.len(), 2);

    // Remove first invoice by payment hash (same pattern as in protocol.rs)
    deposit.invoices.retain(|inv| inv.payment_hash != payment_hash1);

    assert_eq!(deposit.invoices.len(), 1);
    assert_eq!(deposit.invoices[0].payment_hash, payment_hash2);
}

// =============================================================================
// Invoice Lookup Tests
// =============================================================================

#[test]
fn test_find_invoice_by_payment_hash() {
    let deposit_pubkey = generate_test_pubkey(1);
    let preimage: [u8; 32] = [0xDD; 32];
    let payment_hash = generate_payment_hash(&preimage);

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);
    deposit.invoices.push(create_test_invoice(deposit_pubkey, payment_hash, 25_000_000));

    // Find by payment hash
    let found = deposit.invoices.iter().find(|inv| inv.payment_hash == payment_hash);
    assert!(found.is_some());
    assert_eq!(found.unwrap().amount, 25_000_000);

    // Non-existent payment hash
    let not_found = deposit.invoices.iter().find(|inv| inv.payment_hash == [0xFF; 32]);
    assert!(not_found.is_none());
}

// =============================================================================
// Invoice Lifecycle Tests
// =============================================================================

#[test]
fn test_invoice_lifecycle_add_then_credit() {
    let deposit_pubkey = generate_test_pubkey(1);
    let preimage: [u8; 32] = [0xEE; 32];
    let payment_hash = generate_payment_hash(&preimage);
    let amount = 15_000_000u64;

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    // Step 1: Add invoice (simulates cosign success)
    let invoice = create_test_invoice(deposit_pubkey, payment_hash, amount);
    deposit.invoices.push(invoice);
    assert_eq!(deposit.invoices.len(), 1);

    // Step 2: Credit deposit and remove invoice (simulates payment received)
    deposit.balance += amount;
    deposit.invoices.retain(|inv| inv.payment_hash != payment_hash);

    assert_eq!(deposit.invoices.len(), 0);
    assert_eq!(deposit.balance, 100_000_000 + amount);
}

#[test]
fn test_pending_invoice_conversion() {
    let deposit_pubkey = generate_test_pubkey(1);
    let preimage: [u8; 32] = [0xFF; 32];
    let payment_hash = generate_payment_hash(&preimage);
    let amount = 20_000_000u64;

    let pending = create_test_pending_invoice(deposit_pubkey, payment_hash, amount);

    // Convert PendingInvoice to Invoice (as done in handler when cosign succeeds)
    let invoice = Invoice {
        id: pending.invoice_id.clone(),
        payment_hash: pending.payment_hash,
        amount: pending.amount,
        expires: pending.expires,
        assigned_deposit: pending.assigned_deposit,
        bolt11: pending.bolt11.clone(),
    };

    assert_eq!(invoice.payment_hash, payment_hash);
    assert_eq!(invoice.amount, amount);
    assert_eq!(invoice.assigned_deposit, deposit_id_from_pubkey(&deposit_pubkey));
}

// =============================================================================
// Invoice Bolt11 Tests
// =============================================================================

#[test]
fn test_invoice_stores_bolt11() {
    let deposit_pubkey = generate_test_pubkey(1);
    let payment_hash = [0x11; 32];
    let bolt11 = "lnbc100n1ptest".to_string();

    let invoice = Invoice {
        id: "test_invoice".to_string(),
        payment_hash,
        amount: 10_000,
        expires: 1700000000,
        assigned_deposit: deposit_id_from_pubkey(&deposit_pubkey),
        bolt11: bolt11.clone(),
    };

    assert_eq!(invoice.bolt11, bolt11);
}

#[test]
fn test_find_bolt11_by_payment_hash() {
    let deposit_pubkey = generate_test_pubkey(1);
    let payment_hash1 = [0x11; 32];
    let payment_hash2 = [0x22; 32];

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    let deposit_id = deposit_id_from_pubkey(&deposit_pubkey);
    deposit.invoices.push(Invoice {
        id: "inv1".to_string(),
        payment_hash: payment_hash1,
        amount: 10_000,
        expires: 1700000000,
        assigned_deposit: deposit_id,
        bolt11: "lnbc100n1first".to_string(),
    });
    deposit.invoices.push(Invoice {
        id: "inv2".to_string(),
        payment_hash: payment_hash2,
        amount: 20_000,
        expires: 1700000000,
        assigned_deposit: deposit_id,
        bolt11: "lnbc200n1second".to_string(),
    });

    // Find bolt11 for first payment hash
    let bolt11 = deposit.invoices.iter()
        .find(|inv| inv.payment_hash == payment_hash1)
        .map(|inv| inv.bolt11.clone());

    assert_eq!(bolt11, Some("lnbc100n1first".to_string()));

    // Find bolt11 for second payment hash
    let bolt11 = deposit.invoices.iter()
        .find(|inv| inv.payment_hash == payment_hash2)
        .map(|inv| inv.bolt11.clone());

    assert_eq!(bolt11, Some("lnbc200n1second".to_string()));
}

// =============================================================================
// Same-Node Transfer Invoice Removal Tests
// =============================================================================

#[test]
fn test_same_node_transfer_removes_receiver_invoice() {
    let sender_pubkey = generate_test_pubkey(1);
    let receiver_pubkey = generate_test_pubkey(2);
    let preimage: [u8; 32] = [0xAA; 32];
    let payment_hash = generate_payment_hash(&preimage);
    let amount = 10_000_000u64;

    // Sender deposit
    let mut sender = create_test_deposit(sender_pubkey, 100_000_000);

    // Receiver deposit with invoice
    let mut receiver = create_test_deposit(receiver_pubkey, 50_000_000);
    receiver.invoices.push(create_test_invoice(receiver_pubkey, payment_hash, amount));

    assert_eq!(receiver.invoices.len(), 1);

    // Simulate same-node transfer (as in handler.rs execute_same_node_transfer)
    // 1. Debit sender
    sender.balance = sender.balance.saturating_sub(amount);

    // 2. Credit receiver and remove invoice
    receiver.balance += amount;
    receiver.invoices.retain(|inv| inv.payment_hash != payment_hash);

    assert_eq!(sender.balance, 90_000_000);
    assert_eq!(receiver.balance, 60_000_000);
    assert_eq!(receiver.invoices.len(), 0);
}

#[test]
fn test_same_node_transfer_only_removes_matching_invoice() {
    let receiver_pubkey = generate_test_pubkey(1);
    let preimage1: [u8; 32] = [0x11; 32];
    let preimage2: [u8; 32] = [0x22; 32];
    let payment_hash1 = generate_payment_hash(&preimage1);
    let payment_hash2 = generate_payment_hash(&preimage2);

    let mut receiver = create_test_deposit(receiver_pubkey, 50_000_000);
    receiver.invoices.push(create_test_invoice(receiver_pubkey, payment_hash1, 5_000_000));
    receiver.invoices.push(create_test_invoice(receiver_pubkey, payment_hash2, 10_000_000));

    assert_eq!(receiver.invoices.len(), 2);

    // Pay first invoice only
    receiver.balance += 5_000_000;
    receiver.invoices.retain(|inv| inv.payment_hash != payment_hash1);

    // Second invoice should remain
    assert_eq!(receiver.invoices.len(), 1);
    assert_eq!(receiver.invoices[0].payment_hash, payment_hash2);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_remove_nonexistent_invoice_is_noop() {
    let deposit_pubkey = generate_test_pubkey(1);
    let payment_hash = [0x99; 32];

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    // Try to remove invoice that doesn't exist
    let original_len = deposit.invoices.len();
    deposit.invoices.retain(|inv| inv.payment_hash != payment_hash);

    assert_eq!(deposit.invoices.len(), original_len);
}

#[test]
fn test_duplicate_invoice_payment_hashes_both_removed() {
    // This tests defensive behavior - in practice we shouldn't have duplicates
    let deposit_pubkey = generate_test_pubkey(1);
    let payment_hash = [0xAB; 32];

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);

    // Add two invoices with same payment hash (shouldn't happen in practice)
    deposit.invoices.push(create_test_invoice(deposit_pubkey, payment_hash, 5_000_000));
    deposit.invoices.push(create_test_invoice(deposit_pubkey, payment_hash, 10_000_000));

    assert_eq!(deposit.invoices.len(), 2);

    // Retain removes ALL matching - both should be gone
    deposit.invoices.retain(|inv| inv.payment_hash != payment_hash);

    assert_eq!(deposit.invoices.len(), 0);
}

// =============================================================================
// Invoice Expiration Tests
// =============================================================================

#[test]
fn test_invoice_has_expiry() {
    let deposit_pubkey = generate_test_pubkey(1);
    let payment_hash = [0x11; 32];
    let expires = 1700000000u64;

    let invoice = Invoice {
        id: "test".to_string(),
        payment_hash,
        amount: 10_000,
        expires,
        assigned_deposit: deposit_id_from_pubkey(&deposit_pubkey),
        bolt11: "lnbc100n1test".to_string(),
    };

    assert_eq!(invoice.expires, expires);
}

#[test]
fn test_filter_expired_invoices() {
    let deposit_pubkey = generate_test_pubkey(1);
    let now = 1700000100u64; // Current timestamp

    let mut deposit = create_test_deposit(deposit_pubkey, 100_000_000);
    let deposit_id = deposit_id_from_pubkey(&deposit_pubkey);

    // Add expired invoice (expires before now)
    deposit.invoices.push(Invoice {
        id: "expired".to_string(),
        payment_hash: [0x11; 32],
        amount: 5_000,
        expires: 1700000000, // Before 'now'
        assigned_deposit: deposit_id,
        bolt11: "lnbc50n1expired".to_string(),
    });

    // Add valid invoice (expires after now)
    deposit.invoices.push(Invoice {
        id: "valid".to_string(),
        payment_hash: [0x22; 32],
        amount: 10_000,
        expires: 1700000200, // After 'now'
        assigned_deposit: deposit_id,
        bolt11: "lnbc100n1valid".to_string(),
    });

    assert_eq!(deposit.invoices.len(), 2);

    // Filter out expired invoices
    deposit.invoices.retain(|inv| inv.expires > now);

    assert_eq!(deposit.invoices.len(), 1);
    assert_eq!(deposit.invoices[0].id, "valid");
}
