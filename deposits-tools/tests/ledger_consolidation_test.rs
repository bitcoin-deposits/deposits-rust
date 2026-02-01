//! Tests for unified ledger storage with LedgerRole
//!
//! These tests verify:
//! 1. Ledger creation with different roles (Operator, Partner, Auditor)
//! 2. Role-based behavior differences
//! 3. Unified storage lookup patterns
//! 4. Role transitions and validation

#![cfg(feature = "bitcoin-deposits")]

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_ldk::handler::ledger_ext::{Ledger, LedgerRole};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// =============================================================================
// Test Helpers
// =============================================================================

/// Generate a test public key from a seed byte
fn generate_test_pubkey(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[31] = if seed == 0 { 1 } else { seed };
    let sk = SecretKey::from_slice(&secret).unwrap();
    PublicKey::from_secret_key(&secp, &sk)
}

// =============================================================================
// LedgerRole Basic Tests
// =============================================================================

#[test]
fn test_ledger_role_operator() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![],
        "test_address".to_string(),
    );

    assert!(ledger.is_operator());
    assert!(!ledger.is_partner());
    assert_eq!(ledger.role, LedgerRole::Operator);
}

#[test]
fn test_ledger_role_partner() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Partner,
        vec![],
        "test_address".to_string(),
    );

    assert!(!ledger.is_operator());
    assert!(ledger.is_partner());
    assert_eq!(ledger.role, LedgerRole::Partner);
}

#[test]
fn test_ledger_role_auditor() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Auditor,
        vec![],
        "test_address".to_string(),
    );

    assert!(!ledger.is_operator());
    assert!(!ledger.is_partner());
    assert_eq!(ledger.role, LedgerRole::Auditor);
}

#[test]
fn test_new_as_operator_helper() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Ledger::new_as_operator(
        operator,
        partner,
        "test_address".to_string(),
    );

    assert!(ledger.is_operator());
    assert_eq!(ledger.role, LedgerRole::Operator);
    assert_eq!(ledger.state.operator_key, operator);
    assert_eq!(ledger.state.partner_key, partner);
}

// =============================================================================
// Unified Storage Pattern Tests
// =============================================================================

/// Test the unified ledger storage pattern (simulating what handler.rs does)
#[test]
fn test_unified_ledger_storage() {
    // Simulate the unified ledger storage: HashMap<(operator, partner), Ledger>
    let mut ledgers: HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>> = HashMap::new();

    let alice = generate_test_pubkey(1);
    let bob = generate_test_pubkey(2);
    let charlie = generate_test_pubkey(3);

    // Alice as operator with Bob
    let alice_bob_ledger = Ledger::new(
        alice,
        bob,
        LedgerRole::Operator,
        vec![],
        "alice_bob_addr".to_string(),
    );
    ledgers.insert((alice, bob), Arc::new(RwLock::new(alice_bob_ledger)));

    // Bob as operator with Alice (bidirectional - separate ledger)
    let bob_alice_ledger = Ledger::new(
        bob,
        alice,
        LedgerRole::Operator,
        vec![],
        "bob_alice_addr".to_string(),
    );
    ledgers.insert((bob, alice), Arc::new(RwLock::new(bob_alice_ledger)));

    // Charlie as partner on Alice→Bob ledger
    let charlie_audit_ledger = Ledger::new(
        alice,
        bob,
        LedgerRole::Auditor,  // Charlie is auditing this ledger
        vec![],
        "alice_bob_addr".to_string(),
    );
    // Note: In real system, auditor wouldn't store in same HashMap
    // This is just to demonstrate role differentiation

    // Verify we can look up ledgers correctly
    assert_eq!(ledgers.len(), 2);
    assert!(ledgers.contains_key(&(alice, bob)));
    assert!(ledgers.contains_key(&(bob, alice)));

    // Verify roles
    {
        let alice_bob = ledgers.get(&(alice, bob)).unwrap().read().unwrap();
        assert!(alice_bob.is_operator());
    }
    {
        let bob_alice = ledgers.get(&(bob, alice)).unwrap().read().unwrap();
        assert!(bob_alice.is_operator());
    }
}

/// Test looking up ledgers by either key format
#[test]
fn test_ledger_lookup_patterns() {
    let mut ledgers: HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>> = HashMap::new();

    let alice = generate_test_pubkey(1);
    let bob = generate_test_pubkey(2);

    // Store ledger where Alice is operator
    let ledger = Ledger::new(
        alice,
        bob,
        LedgerRole::Operator,
        vec![],
        "addr".to_string(),
    );
    ledgers.insert((alice, bob), Arc::new(RwLock::new(ledger)));

    // Pattern 1: Direct lookup when we know the key format
    assert!(ledgers.get(&(alice, bob)).is_some());
    assert!(ledgers.get(&(bob, alice)).is_none());

    // Pattern 2: Try both key formats (common in handler.rs)
    fn find_ledger<'a>(
        ledgers: &'a HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>>,
        node_a: PublicKey,
        node_b: PublicKey,
    ) -> Option<&'a Arc<RwLock<Ledger>>> {
        ledgers.get(&(node_a, node_b))
            .or_else(|| ledgers.get(&(node_b, node_a)))
    }

    // Should find regardless of order
    assert!(find_ledger(&ledgers, alice, bob).is_some());
    assert!(find_ledger(&ledgers, bob, alice).is_some());
}

// =============================================================================
// Role-Based Behavior Tests
// =============================================================================

#[test]
fn test_role_based_state_access() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    // Create operator ledger
    let op_ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![],
        "addr".to_string(),
    );

    // Create partner ledger (same channel, different perspective)
    let partner_ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Partner,
        vec![],
        "addr".to_string(),
    );

    // Both should have same operator/partner IDs
    assert_eq!(op_ledger.state.operator_key, partner_ledger.state.operator_key);
    assert_eq!(op_ledger.state.partner_key, partner_ledger.state.partner_key);

    // But different roles
    assert_ne!(op_ledger.role, partner_ledger.role);
    assert!(op_ledger.is_operator());
    assert!(partner_ledger.is_partner());
}

#[test]
fn test_multiple_ledgers_same_channel() {
    // Demonstrates that a channel has TWO ledgers (bidirectional)
    let alice = generate_test_pubkey(1);
    let bob = generate_test_pubkey(2);

    let mut ledgers: HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>> = HashMap::new();

    // Ledger 1: Alice → Bob (Alice is operator)
    let alice_to_bob = Ledger::new(
        alice,
        bob,
        LedgerRole::Operator,
        vec![],
        "alice_addr".to_string(),
    );
    ledgers.insert((alice, bob), Arc::new(RwLock::new(alice_to_bob)));

    // Ledger 2: Bob → Alice (Bob is operator)
    let bob_to_alice = Ledger::new(
        bob,
        alice,
        LedgerRole::Operator,
        vec![],
        "bob_addr".to_string(),
    );
    ledgers.insert((bob, alice), Arc::new(RwLock::new(bob_to_alice)));

    // Both exist and are independent
    assert_eq!(ledgers.len(), 2);

    // Each party is operator of their own ledger
    {
        let l1 = ledgers.get(&(alice, bob)).unwrap().read().unwrap();
        assert_eq!(l1.state.operator_key, alice);
        assert!(l1.is_operator());
    }
    {
        let l2 = ledgers.get(&(bob, alice)).unwrap().read().unwrap();
        assert_eq!(l2.state.operator_key, bob);
        assert!(l2.is_operator());
    }
}

// =============================================================================
// Quorum Member Tests
// =============================================================================

#[test]
fn test_ledger_with_quorum_members() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);
    let quorum_member = generate_test_pubkey(3);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![quorum_member],
        "addr".to_string(),
    );

    assert_eq!(ledger.state.quorum_members.len(), 1);
    assert!(ledger.state.quorum_members.contains(&quorum_member));
}

#[test]
fn test_ledger_multiple_quorum_members() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);
    let qm1 = generate_test_pubkey(3);
    let qm2 = generate_test_pubkey(4);
    let qm3 = generate_test_pubkey(5);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![qm1, qm2, qm3],
        "addr".to_string(),
    );

    assert_eq!(ledger.state.quorum_members.len(), 3);
    assert!(ledger.state.quorum_members.contains(&qm1));
    assert!(ledger.state.quorum_members.contains(&qm2));
    assert!(ledger.state.quorum_members.contains(&qm3));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_ledger_empty_address() {
    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![],
        String::new(),
    );

    assert!(ledger.state.ledger_address.is_empty());
}

#[test]
fn test_ledger_same_operator_partner_key() {
    // Edge case: What if operator == partner? (shouldn't happen in practice)
    let same_key = generate_test_pubkey(1);

    let ledger = Ledger::new(
        same_key,
        same_key,
        LedgerRole::Operator,
        vec![],
        "addr".to_string(),
    );

    // Should still work structurally
    assert_eq!(ledger.state.operator_key, ledger.state.partner_key);
    assert!(ledger.is_operator());
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

#[test]
fn test_concurrent_ledger_reads() {
    use std::thread;

    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Arc::new(RwLock::new(Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![],
        "addr".to_string(),
    )));

    let mut handles = vec![];

    // Spawn multiple readers
    for i in 0..10 {
        let ledger_clone = Arc::clone(&ledger);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let guard = ledger_clone.read().unwrap();
                assert!(guard.is_operator());
                assert_eq!(guard.state.operator_key, operator);
                drop(guard);
            }
            i // Return thread id for verification
        });
        handles.push(handle);
    }

    // All threads should complete without deadlock
    for handle in handles {
        let thread_id = handle.join().unwrap();
        assert!(thread_id < 10);
    }
}

#[test]
fn test_concurrent_ledger_writes() {
    use std::thread;
    use std::sync::atomic::{AtomicU64, Ordering};

    let operator = generate_test_pubkey(1);
    let partner = generate_test_pubkey(2);

    let ledger = Arc::new(RwLock::new(Ledger::new(
        operator,
        partner,
        LedgerRole::Operator,
        vec![],
        "addr".to_string(),
    )));

    let write_count = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    // Spawn writers
    for _ in 0..5 {
        let ledger_clone = Arc::clone(&ledger);
        let write_count_clone = Arc::clone(&write_count);

        let handle = thread::spawn(move || {
            for i in 0..20 {
                let mut guard = ledger_clone.write().unwrap();
                // Modify something
                guard.state.ledger_address = format!("addr_{}", i);
                write_count_clone.fetch_add(1, Ordering::SeqCst);
                drop(guard);
            }
        });
        handles.push(handle);
    }

    // All threads should complete
    for handle in handles {
        handle.join().unwrap();
    }

    let total_writes = write_count.load(Ordering::SeqCst);
    assert_eq!(total_writes, 5 * 20);
}

// =============================================================================
// HashMap Key Tests
// =============================================================================

#[test]
fn test_pubkey_tuple_as_hashmap_key() {
    let alice = generate_test_pubkey(1);
    let bob = generate_test_pubkey(2);

    let mut map: HashMap<(PublicKey, PublicKey), String> = HashMap::new();

    map.insert((alice, bob), "alice_to_bob".to_string());
    map.insert((bob, alice), "bob_to_alice".to_string());

    // Keys are ordered - (A,B) != (B,A)
    assert_eq!(map.get(&(alice, bob)), Some(&"alice_to_bob".to_string()));
    assert_eq!(map.get(&(bob, alice)), Some(&"bob_to_alice".to_string()));
    assert_ne!(map.get(&(alice, bob)), map.get(&(bob, alice)));
}
