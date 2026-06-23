//! Adversarial tests: attempt to steal funds using a minority of network funds.
//!
//! Each test simulates a specific attack vector against the protocol.
//! The goal is to verify that an attacker controlling fewer than majority
//! of quorum members cannot extract more value than their own collateral.
//!
//! Network topology for these tests:
//!   4 operators (alice, bob, charlie, diana), each with 1M sat reserves
//!   Each operator's ledger has 3 quorum members (the other 3 operators)
//!   Reserves locked in Taproot with threshold spending:
//!     Tier 0: 3-of-4 majority (immediate)
//!     Tier 1: 1-of-4 minority (after 1008 blocks)
//!     Tier 2: operator only (after 2016 blocks)
//!
//! Attacker controls: 1 operator (alice) = 25% of network
//! Target: extract more than alice's own 1M sat reserves

use deposits_core::ledger::Ledger;
use deposits_test::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{
    compute_deposit_id, ConformanceViolation, DisputeState, FeeStructure, QuorumState,
};
use deposits_protocol::TlvDecode;

/// Set up a 4-operator network with quorum and collateral.
fn setup_adversarial_network() -> TestNetwork {
    let mut net = TestNetwork::new(&["alice", "bob", "charlie", "diana"], 1_000_000);

    // Snapshot all operators for quorum setup
    let snapshots: Vec<_> = net
        .operators
        .iter()
        .map(|o| Operator {
            name: o.name.clone(),
            secret_key: o.secret_key,
            public_key: o.public_key,
            ledger: o.ledger.clone(),
        })
        .collect();

    // Each operator adds the other 3 as quorum members
    for op_name in &["alice", "bob", "charlie", "diana"] {
        for member in &snapshots {
            if member.name == *op_name {
                continue;
            }
            let lid = hex::encode(member.ledger.state.ledger_id);
            net.op_mut(op_name).add_quorum_member(member, &lid);
        }
        net.op_mut(op_name).begin_quorum(1_000_000);
    }

    net
}

// =========================================================================
// Attack 1: Operator inflates deposits beyond reserves
// =========================================================================

#[test]
fn attack_operator_inflates_deposits() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);

    // Alice opens a deposit and credits it honestly
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 500_000, [0xAA; 32]);

    // Attack: Alice credits more than her reserves allow
    net.op_mut("alice")
        .credit_deposit(deposit_id, 600_000, [0xBB; 32]);
    // Total deposits: 1.1M, reserves: 1M — over-reserved

    // Watcher (bob) should detect the violation
    let mut watcher = net.create_watcher("alice");
    let violations = net.op("alice").sync_to_checked(&mut watcher);

    assert!(
        !violations.is_empty(),
        "Watcher must detect over-reserve inflation"
    );
    assert!(violations
        .iter()
        .any(|v| matches!(v, ConformanceViolation::InsufficientReserves { .. })));
}

// =========================================================================
// Attack 2: Operator double-credits the same payment
// =========================================================================

#[test]
fn attack_double_credit_same_payment() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);

    // First credit succeeds
    net.op_mut("alice")
        .credit_deposit(deposit_id, 500_000, [0xAA; 32]);

    // Attack: try to credit the same payment hash again
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xAA; 32], // same hash
            deposit_id,
            amount: 500_000,
            invoice_id: "dup".to_string(),
            sequence_number: 99,
            wallet_authorization: None,
        });

    assert!(result.is_err(), "Double credit must be rejected");
}

// =========================================================================
// Attack 3: Operator withdraws more than deposited
// =========================================================================

#[test]
fn attack_withdraw_exceeds_balance() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Attack: try to lock withdrawal for more than balance
    let withdrawal_id = [0x01; 32];
    let proto = LedgerOperation::OnchainLock {
        deposit_id,
        amount: 200_000,
        fee_sats: 1_000,
        destination_address: "bcrt1qattacker".to_string(),
        withdrawal_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: deposits_protocol::DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &user.secret_key)
        .expect("OnchainLock signs via dep-17 preimage");

    let result = net.op_mut("alice").ledger.apply_operation(&op);

    assert!(
        result.is_err(),
        "Withdrawal exceeding balance must be rejected"
    );
}

// =========================================================================
// Attack 4: Forge witness signature on invoice lock
// =========================================================================

#[test]
fn attack_forged_invoice_witness() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 500_000, [0xAA; 32]);

    // Attack: lock an invoice with a forged signature (signed by the attacker, not
    // the depositor). sign_op produces a real signature over the dep-17 preimage —
    // the forgery is using the wrong key, so the descriptor (which expects the
    // depositor's pubkey) won't be satisfied by the witness.
    let attacker_key = net.create_depositor("attacker", 99);
    let payment_id = [0x01; 32];
    let proto = LedgerOperation::InvoiceLock {
        deposit_id,
        amount: 500_000,
        payment_id,
        sequence_number: net.op("alice").ledger.state.sequence + 1,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: deposits_protocol::DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &attacker_key.secret_key)
        .expect("InvoiceLock signs via dep-17 preimage");

    // apply_with_verifier must surface a violation (operator path)
    let (_, violations) = net
        .op("alice")
        .ledger
        .state
        .apply_with_verifier(
            &op,
            &deposits_core::dep16::Dep16Authorizer::new(),
            0,
        )
        .expect("apply succeeds; the rejection is in conformance");
    assert!(
        !violations.is_empty(),
        "Forged witness must be flagged: {:?}",
        violations
    );
}

// =========================================================================
// Attack 5: Operate ledger during dispute (bypass state gate)
// =========================================================================

#[test]
fn attack_operate_during_dispute() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 500_000, [0xAA; 32]);

    // Bob opens dispute on alice's ledger
    let dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "non-conforming".to_string(),
        anchor_block_hash: None,
        anchor_block_height: None,
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute)
        .unwrap();

    // Attack: alice tries to credit more funds during dispute
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xCC; 32],
            deposit_id,
            amount: 500_000,
            invoice_id: "steal".to_string(),
            sequence_number: 99,
            wallet_authorization: None,
        });
    assert!(result.is_err(), "Credits must be blocked during dispute");

    // Attack: try to open new deposit during dispute
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DepositOpen {
            deposit_id: compute_deposit_id("pk(evil)"),
            descriptor: "pk(evil)".to_string(),
            fees: Some(FeeStructure::default()),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        });
    assert!(
        result.is_err(),
        "Deposit opens must be blocked during dispute"
    );
}

// =========================================================================
// Attack 6: Claim custody without winning lottery
// =========================================================================

#[test]
fn attack_false_custody_claim() {
    let mut net = setup_adversarial_network();

    // Open dispute
    let dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test".to_string(),
        anchor_block_hash: None,
        anchor_block_height: None,
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute)
        .unwrap();

    // Rebuild quorum for dispute
    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    net.op_mut("alice").add_quorum_member(&bob_snap, "bob_lid");

    // Arm
    let arm = LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
        replacement_collateral: None,
    };
    net.op_mut("alice").ledger.apply_operation(&arm).unwrap();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Armed
    );

    // Attack: alice tries to claim custody (she's the operator being disputed,
    // not a legitimate candidate). The acquire should succeed at the state level
    // since the protocol doesn't validate the entropy selection in apply() —
    // that's done at the node layer. But the state should update.
    let acquire = LedgerOperation::DisputeAcquire {
        new_custodian: net.op("alice").public_key, // alice claims for herself
        claim_txid: [0xCC; 32],
        new_reserves_address: "bcrt1qalice_steals".to_string(),
    };

    // This is a protocol-layer test — apply() doesn't validate entropy winner.
    // The node layer (deposits-node) validates this. At the protocol level,
    // the operation is structurally valid, which is correct — the protocol
    // layer is deterministic state transitions, not policy enforcement.
    let result = net.op_mut("alice").ledger.apply_operation(&acquire);
    // Note: this succeeds at protocol level. Entropy validation happens
    // at the node layer where the block hash is checked against candidates.
    assert!(result.is_ok(), "DisputeAcquire is valid at protocol level");

    // But a watcher should see this and can verify the entropy doesn't
    // actually select alice — that's the node-layer check.
}

// =========================================================================
// Attack 7: Transfer lock with insufficient balance (after partial lock)
// =========================================================================

#[test]
fn attack_drain_via_overlapping_locks() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Lock 80k via invoice
    let payment_id = [0x01; 32];
    net.op_mut("alice")
        .lock_invoice(&user, deposit_id, 80_000, payment_id);

    // Attack: try to lock another 80k (only 20k available)
    let payment_id2 = [0x02; 32];
    let next_seq = net.op("alice").ledger.state.sequence + 1;
    let proto = LedgerOperation::InvoiceLock {
        deposit_id,
        amount: 80_000,
        payment_id: payment_id2,
        sequence_number: next_seq,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: deposits_protocol::DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &user.secret_key)
        .expect("InvoiceLock signs via dep-17 preimage");
    let result = net.op_mut("alice").ledger.apply_operation(&op);

    assert!(
        result.is_err(),
        "Overlapping locks exceeding available balance must be rejected"
    );
}

// =========================================================================
// Attack 8: Replay old operation (sequence number manipulation)
// =========================================================================

#[test]
fn attack_replay_old_credit() {
    let mut net = setup_adversarial_network();
    let user = net.create_depositor("victim", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);

    // Credit 100k with payment hash A
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Record the current state
    let balance_after_credit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap()
        .balance;
    assert_eq!(balance_after_credit, 100_000);

    // Attack: try to replay the same credit with a different sequence number
    // but same payment hash — should be caught by duplicate detection
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xAA; 32], // same hash
            deposit_id,
            amount: 100_000,
            invoice_id: "replay".to_string(),
            sequence_number: 999, // different sequence
            wallet_authorization: None,
        });

    assert!(
        result.is_err(),
        "Replayed credit (same payment hash) must be rejected"
    );
}

// =========================================================================
// Attack 9: Watcher detects all violations in a malicious sequence
// =========================================================================

#[test]
fn attack_watcher_detects_malicious_sequence() {
    let mut net = TestNetwork::new(&["alice"], 500_000); // low reserves
    let mut watcher = net.create_watcher("alice");
    let user1 = net.create_depositor("user1", 10);
    let user2 = net.create_depositor("user2", 20);

    let did1 = net.op_mut("alice").open_deposit(&user1);
    let did2 = net.op_mut("alice").open_deposit(&user2);

    // Credit user1 within reserves
    net.op_mut("alice")
        .credit_deposit(did1, 300_000, [0x01; 32]);

    // Credit user2 — pushes over reserves
    net.op_mut("alice")
        .credit_deposit(did2, 300_000, [0x02; 32]);
    // Total: 600k deposits, 500k reserves

    // Sync all to watcher
    let violations = net.op("alice").sync_to_checked(&mut watcher);

    // Should detect exactly one violation (the second credit)
    let reserve_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, ConformanceViolation::InsufficientReserves { .. }))
        .collect();

    assert_eq!(
        reserve_violations.len(),
        1,
        "Should detect exactly one over-reserve violation"
    );

    // Watcher still tracked the full state
    assert_eq!(watcher.state.total_deposit_balance(), 600_000);
    assert_eq!(watcher.state.deposits.len(), 2);
}
