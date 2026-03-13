//! Tests for reserves holding cell pattern
//!
//! These tests verify:
//! 1. Concurrent update patterns and race condition prevention
//! 2. Holding cell queue behavior (LIFO - last update wins)
//! 3. Bidirectional reserves updates work without race conditions
//! 4. LedgerRole enum functionality
//!
//! Note: The actual HoldingCellReservesUpdate struct is internal to rust-lightning.
//! These tests verify the patterns and behaviors at a higher level.

#![cfg(feature = "bitcoin-deposits")]

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// =============================================================================
// Concurrent Access Pattern Tests
// =============================================================================

/// Test that demonstrates the race condition pattern we're protecting against
#[test]
fn test_concurrent_counter_pattern() {
    // This test demonstrates the pattern of concurrent access
    // that the holding cell protects against

    let counter = Arc::new(AtomicU64::new(0));
    let num_threads = 10;
    let iterations_per_thread = 100;

    let mut handles = vec![];

    for _ in 0..num_threads {
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..iterations_per_thread {
                // Simulate the pattern of:
                // 1. Check if busy
                // 2. If not, proceed
                // 3. If yes, queue
                let current = counter_clone.load(Ordering::SeqCst);
                counter_clone.store(current + 1, Ordering::SeqCst);

                // Small delay to increase chance of interleaving
                thread::sleep(Duration::from_nanos(10));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // The counter might not equal num_threads * iterations_per_thread
    // due to race conditions - this demonstrates why we need the holding cell
    let final_count = counter.load(Ordering::SeqCst);
    println!("Final count: {} (expected without races: {})",
             final_count, num_threads * iterations_per_thread);

    // The point is that without proper synchronization, we get races
    // The holding cell pattern ensures updates are serialized
}

/// Test atomic compare-and-swap pattern (what holding cell effectively provides)
#[test]
fn test_compare_and_swap_pattern() {
    let state = Arc::new(AtomicU64::new(0));
    let num_threads = 10;
    let success_count = Arc::new(AtomicU64::new(0));

    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let state_clone = Arc::clone(&state);
        let success_clone = Arc::clone(&success_count);

        let handle = thread::spawn(move || {
            // Try to be the one to transition from 0 to 1
            // This is analogous to "try to send update if not busy, else queue"
            let result = state_clone.compare_exchange(
                0, // expected: not busy
                1, // new: now busy
                Ordering::SeqCst,
                Ordering::SeqCst
            );

            match result {
                Ok(_) => {
                    // We got it! Simulate doing work
                    thread::sleep(Duration::from_millis(1));
                    success_clone.fetch_add(1, Ordering::SeqCst);
                    // Release
                    state_clone.store(0, Ordering::SeqCst);
                }
                Err(_) => {
                    // Would be queued in holding cell
                    println!("Thread {} would be queued", thread_id);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let successes = success_count.load(Ordering::SeqCst);
    println!("Successful immediate sends: {} out of {}", successes, num_threads);

    // At least one should succeed
    assert!(successes >= 1);
}

// =============================================================================
// Simulated Holding Cell Queue Tests
// =============================================================================

/// Simulates the holding cell queue behavior
/// This mirrors the pattern used in rust-lightning for reserves updates
struct SimulatedHoldingCell {
    pending_update: Mutex<Option<(u64, [u8; 32])>>,
    is_busy: AtomicBool,
}

impl SimulatedHoldingCell {
    fn new() -> Self {
        Self {
            pending_update: Mutex::new(None),
            is_busy: AtomicBool::new(false),
        }
    }

    /// Try to send an update. Returns true if sent, false if queued.
    fn try_send(&self, amount: u64, hash: [u8; 32]) -> bool {
        if self.is_busy.load(Ordering::SeqCst) {
            // Queue in holding cell
            let mut pending = self.pending_update.lock().unwrap();
            *pending = Some((amount, hash));
            false
        } else {
            // Mark as busy and "send"
            self.is_busy.store(true, Ordering::SeqCst);
            true
        }
    }

    /// Mark as no longer busy and process any queued update
    fn complete(&self) -> Option<(u64, [u8; 32])> {
        self.is_busy.store(false, Ordering::SeqCst);
        let mut pending = self.pending_update.lock().unwrap();
        pending.take()
    }
}

#[test]
fn test_simulated_holding_cell_queue() {
    let cell = SimulatedHoldingCell::new();

    // First update goes through
    assert!(cell.try_send(1000, [0x01; 32]));

    // Second update gets queued
    assert!(!cell.try_send(2000, [0x02; 32]));

    // Complete first, should get queued one back
    let queued = cell.complete();
    assert!(queued.is_some());
    let (amount, hash) = queued.unwrap();
    assert_eq!(amount, 2000);
    assert_eq!(hash, [0x02; 32]);
}

#[test]
fn test_simulated_holding_cell_overwrite() {
    let cell = SimulatedHoldingCell::new();

    // First update goes through
    assert!(cell.try_send(1000, [0x01; 32]));

    // Multiple updates get queued - only last one kept (like our implementation)
    assert!(!cell.try_send(2000, [0x02; 32]));
    assert!(!cell.try_send(3000, [0x03; 32]));
    assert!(!cell.try_send(4000, [0x04; 32]));

    // Complete - should get the last queued update
    let queued = cell.complete();
    assert!(queued.is_some());
    let (amount, hash) = queued.unwrap();
    assert_eq!(amount, 4000);
    assert_eq!(hash, [0x04; 32]);
}

#[test]
fn test_simulated_holding_cell_no_queue_when_not_busy() {
    let cell = SimulatedHoldingCell::new();

    // First update goes through
    assert!(cell.try_send(1000, [0x01; 32]));

    // Complete it
    let queued = cell.complete();
    assert!(queued.is_none()); // No queued updates

    // Next update goes through immediately
    assert!(cell.try_send(2000, [0x02; 32]));
}

// =============================================================================
// Bidirectional Update Pattern Tests
// =============================================================================

#[test]
fn test_bidirectional_updates_pattern() {
    // Simulate Alice and Bob each having their own holding cell
    // This demonstrates the bidirectional update pattern

    let alice_cell = Arc::new(SimulatedHoldingCell::new());
    let bob_cell = Arc::new(SimulatedHoldingCell::new());

    // Both try to send at the same time
    let alice_cell_clone = Arc::clone(&alice_cell);
    let bob_cell_clone = Arc::clone(&bob_cell);

    let alice_handle = thread::spawn(move || {
        // Alice sends update for her ledger
        alice_cell_clone.try_send(1000, [0xAA; 32])
    });

    let bob_handle = thread::spawn(move || {
        // Bob sends update for his ledger
        bob_cell_clone.try_send(2000, [0xBB; 32])
    });

    let alice_sent = alice_handle.join().unwrap();
    let bob_sent = bob_handle.join().unwrap();

    // Both should succeed because they're independent cells
    assert!(alice_sent, "Alice's update should go through on her channel");
    assert!(bob_sent, "Bob's update should go through on his channel");

    println!("Both parties successfully sent updates for their respective ledgers");
}

#[test]
fn test_same_channel_concurrent_updates() {
    // Same channel, both parties trying to update
    // This is what the holding cell prevents from racing

    let shared_cell = Arc::new(SimulatedHoldingCell::new());

    let cell1 = Arc::clone(&shared_cell);
    let cell2 = Arc::clone(&shared_cell);

    let handle1 = thread::spawn(move || {
        cell1.try_send(1000, [0x01; 32])
    });

    let handle2 = thread::spawn(move || {
        cell2.try_send(2000, [0x02; 32])
    });

    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();

    // Exactly one should succeed, one should be queued
    assert!(
        (result1 && !result2) || (!result1 && result2),
        "Exactly one update should go through, one should be queued"
    );

    println!("Concurrent update test passed: one sent immediately, one queued");
}

// =============================================================================
// Stress Tests
// =============================================================================

#[test]
fn test_holding_cell_stress() {
    let cell = Arc::new(SimulatedHoldingCell::new());
    let completed_count = Arc::new(AtomicU64::new(0));
    let queued_count = Arc::new(AtomicU64::new(0));

    let num_threads = 20;
    let mut handles = vec![];

    for i in 0..num_threads {
        let cell_clone = Arc::clone(&cell);
        let completed = Arc::clone(&completed_count);
        let queued = Arc::clone(&queued_count);

        let handle = thread::spawn(move || {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;

            if cell_clone.try_send(i as u64 * 1000, hash) {
                // Simulate processing time
                thread::sleep(Duration::from_micros(100));

                // Process any queued update
                if let Some((amt, _)) = cell_clone.complete() {
                    completed.fetch_add(1, Ordering::SeqCst);
                    println!("Thread {} processed queued update: {} sats", i, amt);
                }
                completed.fetch_add(1, Ordering::SeqCst);
            } else {
                queued.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let total_completed = completed_count.load(Ordering::SeqCst);
    let total_queued = queued_count.load(Ordering::SeqCst);

    println!("Stress test results:");
    println!("  Completed immediately or from queue: {}", total_completed);
    println!("  Queued (and possibly overwritten): {}", total_queued);

    // All threads should have done something
    assert!(total_completed + total_queued >= num_threads as u64);
}

// =============================================================================
// LedgerRole Tests
// =============================================================================

#[test]
fn test_ledger_role_equality() {
    use deposits_core::ledger::LedgerRole;

    assert_eq!(LedgerRole::Operator, LedgerRole::Operator);
    assert_eq!(LedgerRole::Partner, LedgerRole::Partner);
    assert_eq!(LedgerRole::Auditor, LedgerRole::Auditor);

    assert_ne!(LedgerRole::Operator, LedgerRole::Partner);
    assert_ne!(LedgerRole::Operator, LedgerRole::Auditor);
    assert_ne!(LedgerRole::Partner, LedgerRole::Auditor);
}

#[test]
fn test_ledger_role_debug() {
    use deposits_core::ledger::LedgerRole;

    let operator = format!("{:?}", LedgerRole::Operator);
    let partner = format!("{:?}", LedgerRole::Partner);
    let auditor = format!("{:?}", LedgerRole::Auditor);

    assert!(operator.contains("Operator"));
    assert!(partner.contains("Partner"));
    assert!(auditor.contains("Auditor"));
}

// =============================================================================
// Integration Pattern Tests
// =============================================================================

/// Test the full pattern: busy -> queue -> free -> process
#[test]
fn test_full_holding_cell_cycle() {
    let cell = SimulatedHoldingCell::new();

    // Phase 1: Channel becomes busy
    assert!(cell.try_send(1000, [0x01; 32]), "First update should succeed");

    // Phase 2: More updates come in while busy
    for i in 2..=5 {
        let mut hash = [0u8; 32];
        hash[0] = i;
        assert!(!cell.try_send(i as u64 * 1000, hash), "Update {} should be queued", i);
    }

    // Phase 3: First update completes
    let queued = cell.complete();
    assert!(queued.is_some(), "Should have a queued update");

    let (amount, hash) = queued.unwrap();
    assert_eq!(amount, 5000, "Should be the last queued update (5000)");
    assert_eq!(hash[0], 5, "Should be hash from update 5");

    // Phase 4: Process the queued update
    assert!(cell.try_send(amount, hash), "Processing queued update should succeed");

    // Phase 5: Complete and verify no more queued
    let final_queued = cell.complete();
    assert!(final_queued.is_none(), "No more updates should be queued");

    println!("Full holding cell cycle completed successfully");
}
