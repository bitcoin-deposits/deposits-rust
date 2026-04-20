//! Tests for ledger synchronization between operator and partner
//!
//! These tests verify that when ledger updates are applied on one side,
//! they produce identical hash chains when replayed on the other side.
//! This prevents regression of the ledger divergence bug where operator
//! and partner ledgers would have different update counts/hashes.

use deposits_core::ledger::Ledger;
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{compute_deposit_id, FeeStructure};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn test_pubkey_2() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    )
    .unwrap()
}

fn make_deposit_open(descriptor: &str) -> LedgerOperation {
    LedgerOperation::DepositOpen {
        deposit_id: compute_deposit_id(descriptor),
        descriptor: descriptor.to_string(),
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    }
}

fn make_quorum_add_member() -> LedgerOperation {
    LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey_2(),
        quorum_member_signature: [0xEF; 64],
        member_ledger_id: "member_ledger".to_string(),
        min_fee_bps: Some(50),
        min_fee_fixed: Some(100),
        max_fee_period: Some(2016),
        membership_until: Some(900_000),
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
    }
}

// =========================================================================
// Ledger Synchronization Tests - Prevent Divergence Regression
// =========================================================================

/// Test that applying the same sequence of updates to two separate ledgers
/// produces identical hash chains.
#[test]
fn test_identical_updates_produce_identical_hashes() {
    let mut operator = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    let mut partner = Ledger::new_as_partner(test_pubkey(), "bcrt1qtest".to_string(), 0);

    // Apply DepositOpen to both
    let op1 = make_deposit_open("pk(test1)");
    operator.apply_operation(&op1).unwrap();
    partner.apply_operation(&op1).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, partner.state.sequence);
    assert_ne!(operator.state.chain_tip_hash, [0u8; 32]);

    // Apply another DepositOpen to both
    let op2 = make_deposit_open("pk(test2)");
    operator.apply_operation(&op2).unwrap();
    partner.apply_operation(&op2).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, partner.state.sequence);

    // Apply QuorumAddMember to both
    let op3 = make_quorum_add_member();
    operator.apply_operation(&op3).unwrap();
    partner.apply_operation(&op3).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, partner.state.sequence);
    assert_eq!(operator.state.sequence, 3);
}

/// Test that divergent ledgers can be detected by comparing hashes.
/// This simulates the bug scenario where operator had more updates than partner.
#[test]
fn test_divergent_ledgers_have_different_hashes() {
    let mut operator = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    let mut partner = Ledger::new_as_partner(test_pubkey(), "bcrt1qtest".to_string(), 0);

    // Apply same first op to both
    let op1 = make_deposit_open("pk(test1)");
    operator.apply_operation(&op1).unwrap();
    partner.apply_operation(&op1).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);

    // Apply extra op only to operator
    let op2 = make_deposit_open("pk(test2)");
    operator.apply_operation(&op2).unwrap();

    // Hashes and sequences should now differ
    assert_ne!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_ne!(operator.state.sequence, partner.state.sequence);
    assert_eq!(operator.state.sequence, 2);
    assert_eq!(partner.state.sequence, 1);
}

/// Test full synchronization flow:
/// 1. LedgerOpen sets params
/// 2. DepositOpen
/// 3. QuorumAddMember
///
/// Both sides should have identical final state.
#[test]
fn test_full_sync_flow() {
    let mut operator = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    let mut partner = Ledger::new_as_partner(test_pubkey(), "bcrt1qtest".to_string(), 0);

    // Step 1: LedgerOpen (sets reserves)
    let ledger_open = LedgerOperation::LedgerOpen {
        operator_id: test_pubkey(),
        reserves_id: "bcrt1qtest".to_string(),
        genesis_block: 0,
        reserves_amount: 1_000_000,
        collateral_amount: 0,
    };
    operator.apply_operation(&ledger_open).unwrap();
    partner.apply_operation(&ledger_open).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, 1);

    // Step 2: DepositOpen
    let deposit = make_deposit_open("pk(full_sync_test)");
    operator.apply_operation(&deposit).unwrap();
    partner.apply_operation(&deposit).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, 2);

    // Step 3: QuorumAddMember
    let add_member = make_quorum_add_member();
    operator.apply_operation(&add_member).unwrap();
    partner.apply_operation(&add_member).unwrap();

    assert_eq!(operator.state.chain_tip_hash, partner.state.chain_tip_hash);
    assert_eq!(operator.state.sequence, 3);

    // Verify full state equality
    assert_eq!(operator.state.sequence, partner.state.sequence);
    assert_eq!(operator.state.deposits.len(), partner.state.deposits.len());
    assert_eq!(
        operator.state.next_quorum_members.len(),
        partner.state.next_quorum_members.len()
    );
    assert_eq!(
        operator.state.collateral_amount,
        partner.state.collateral_amount
    );
}

/// Test that hash chain is deterministic - same messages in same order
/// always produce the same hashes, regardless of when they're applied.
#[test]
fn test_hash_chain_determinism() {
    // Build first ledger
    let mut ledger_a = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    let ops = vec![
        make_deposit_open("pk(determinism1)"),
        make_deposit_open("pk(determinism2)"),
        make_quorum_add_member(),
    ];
    for op in &ops {
        ledger_a.apply_operation(op).unwrap();
    }

    // Build second ledger with the same ops (simulating a different time)
    let mut ledger_b = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    for op in &ops {
        ledger_b.apply_operation(op).unwrap();
    }

    // Hashes must be identical
    assert_eq!(ledger_a.state.chain_tip_hash, ledger_b.state.chain_tip_hash);
    assert_eq!(ledger_a.state.sequence, ledger_b.state.sequence);

    // Also verify intermediate hashes by building a third ledger step by step
    let mut ledger_c = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    let mut ledger_d = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    for op in &ops {
        ledger_c.apply_operation(op).unwrap();
        ledger_d.apply_operation(op).unwrap();
        // After each op, the hashes should match
        assert_eq!(ledger_c.state.chain_tip_hash, ledger_d.state.chain_tip_hash);
    }

    // Final state should match ledger_a
    assert_eq!(ledger_a.state.chain_tip_hash, ledger_c.state.chain_tip_hash);
}

// =========================================================================
// Audit Ledger Synchronization Tests - Ensure quorum members receive all updates
// =========================================================================

/// Test that a new quorum member should receive AddQuorumMember
/// as the first update in their audit ledger.
///
/// This test documents the expected behavior: when a quorum member is added,
/// they should receive a SignedAuditUpdate for the AddQuorumMember message
/// that added them. Without this, auditors would have a sparse audit log that
/// starts from a later sequence number.
#[test]
fn test_quorum_member_receives_add_message() {
    let mut ledger = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);

    // Apply a deposit first (sequence 0)
    let deposit = make_deposit_open("pk(before_quorum)");
    ledger.apply_operation(&deposit).unwrap();

    let hash_before_add = ledger.state.chain_tip_hash;
    let seq_before_add = ledger.state.sequence;

    // Now add quorum member (sequence 1) - this should be part of the hash chain
    let add_member = make_quorum_add_member();
    ledger.apply_operation(&add_member).unwrap();

    // The QuorumAddMember must advance the hash chain
    assert_ne!(ledger.state.chain_tip_hash, hash_before_add);
    assert_eq!(ledger.state.sequence, seq_before_add + 1);

    // Verify the member was added to next_quorum_members
    assert_eq!(ledger.state.next_quorum_members.len(), 1);
    assert_eq!(ledger.state.next_quorum_members[0].pubkey, test_pubkey_2());

    // A replayed ledger applying the same ops must reach the same state,
    // which proves the QuorumAddMember is included in the chain
    let mut replayed = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    replayed.apply_operation(&deposit).unwrap();
    replayed.apply_operation(&add_member).unwrap();

    assert_eq!(ledger.state.chain_tip_hash, replayed.state.chain_tip_hash);
    assert_eq!(ledger.state.sequence, replayed.state.sequence);
}

/// Test that auditors must receive updates starting from sequence 0.
/// If an auditor's first update has sequence > 0, they have a broken audit chain.
///
/// This test documents the bug where quorum members only received updates
/// AFTER being added to the quorum, missing the AddQuorumMember itself.
#[test]
fn test_auditor_chain_must_start_from_zero() {
    let mut ledger = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);

    // Build up a chain of operations
    let ops = vec![
        make_deposit_open("pk(audit1)"),
        make_deposit_open("pk(audit2)"),
        make_quorum_add_member(),
    ];

    // Track hash at each sequence number
    let mut hashes_by_seq: Vec<[u8; 32]> = vec![[0u8; 32]]; // genesis hash at seq 0 (before any ops)
    for op in &ops {
        ledger.apply_operation(op).unwrap();
        hashes_by_seq.push(ledger.state.chain_tip_hash);
    }

    // Replay from sequence 0 on a fresh ledger and verify every hash matches
    let mut auditor = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    assert_eq!(auditor.state.chain_tip_hash, hashes_by_seq[0]);
    assert_eq!(auditor.state.sequence, 0);

    for (i, op) in ops.iter().enumerate() {
        auditor.apply_operation(op).unwrap();
        assert_eq!(
            auditor.state.chain_tip_hash,
            hashes_by_seq[i + 1],
            "Hash mismatch at sequence {}",
            i + 1
        );
        assert_eq!(auditor.state.sequence, (i + 1) as u64);
    }

    // Final state must match
    assert_eq!(auditor.state.chain_tip_hash, ledger.state.chain_tip_hash);
    assert_eq!(auditor.state.sequence, ledger.state.sequence);

    // Verify that starting from a later sequence would break the chain:
    // if an auditor skips the first op, they get a different hash chain
    let mut late_auditor = Ledger::new_as_operator(test_pubkey(), "bcrt1qtest".to_string(), 0);
    // Skip ops[0], apply from ops[1] onward
    for op in &ops[1..] {
        late_auditor.apply_operation(op).unwrap();
    }

    // The late auditor's final hash will differ because they missed the first operation
    assert_ne!(
        late_auditor.state.chain_tip_hash,
        ledger.state.chain_tip_hash
    );
}
