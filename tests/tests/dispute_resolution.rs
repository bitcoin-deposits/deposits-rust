//! Dispute resolution: enter, arm, acquire/yield state transitions.

use deposits_core::ledger::Ledger;
use deposits_integration_tests::*;
use deposits_protocol::types::{DisputeState, QuorumState};

fn setup_quorum_network() -> TestNetwork {
    let mut net = TestNetwork::new(&["alice", "bob", "charlie"], 1_000_000);

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let charlie_snap = Operator {
        name: "charlie".into(),
        secret_key: net.op("charlie").secret_key,
        public_key: net.op("charlie").public_key,
        ledger: net.op("charlie").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);
    let charlie_lid = hex::encode(charlie_snap.ledger.state.ledger_id);

    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);
    net.op_mut("alice")
        .add_quorum_member(&charlie_snap, &charlie_lid);
    net.op_mut("alice").begin_quorum(1_000_000);
    net.op_mut("alice").record_attestation(&bob_snap, 500_000);
    net.op_mut("alice")
        .record_attestation(&charlie_snap, 500_000);

    net
}

#[test]
fn dispute_enter_changes_state() {
    let mut net = setup_quorum_network();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Normal
    );

    let dispute_op = deposits_protocol::LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test dispute".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute_op)
        .unwrap();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Disputed
    );
    assert_eq!(net.op("alice").ledger.state.quorum_at_fork.len(), 2);
}

#[test]
fn dispute_arm_requires_disputed_state() {
    let mut net = setup_quorum_network();

    let arm_op = deposits_protocol::LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
    };
    let result = net.op_mut("alice").ledger.apply_operation(&arm_op);
    assert!(
        result.is_err(),
        "should reject DisputeArmed in Normal state"
    );
}

#[test]
fn dispute_arm_after_enter_succeeds() {
    let mut net = setup_quorum_network();

    let dispute_op = deposits_protocol::LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute_op)
        .unwrap();

    // Re-add quorum members on the disputed fork
    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let charlie_snap = Operator {
        name: "charlie".into(),
        secret_key: net.op("charlie").secret_key,
        public_key: net.op("charlie").public_key,
        ledger: net.op("charlie").ledger.clone(),
    };
    net.op_mut("alice").add_quorum_member(&bob_snap, "bob_lid");
    net.op_mut("alice")
        .add_quorum_member(&charlie_snap, "charlie_lid");
    net.op_mut("alice").record_attestation(&bob_snap, 500_000);

    let arm_op = deposits_protocol::LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
    };
    net.op_mut("alice").ledger.apply_operation(&arm_op).unwrap();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Armed
    );
}

#[test]
fn dispute_acquire_returns_to_normal() {
    let mut net = setup_quorum_network();

    let dispute_op = deposits_protocol::LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute_op)
        .unwrap();

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    net.op_mut("alice").add_quorum_member(&bob_snap, "bob_lid");
    net.op_mut("alice").record_attestation(&bob_snap, 500_000);

    let arm_op = deposits_protocol::LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
    };
    net.op_mut("alice").ledger.apply_operation(&arm_op).unwrap();

    let acquire_op = deposits_protocol::LedgerOperation::DisputeAcquire {
        new_custodian: net.op("bob").public_key,
        entropy_block_height: 850_000,
        entropy_block_hash: [0xBB; 32],
        spend_txid: [0xCC; 32],
        new_reserves_address: "bcrt1q_bob_new".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&acquire_op)
        .unwrap();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Normal
    );
    assert_eq!(
        net.op("alice").ledger.state.operator_key,
        net.op("bob").public_key
    );
}

#[test]
fn dispute_yield_tombstones_ledger() {
    let mut net = setup_quorum_network();

    let dispute_op = deposits_protocol::LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute_op)
        .unwrap();

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    net.op_mut("alice").add_quorum_member(&bob_snap, "bob_lid");
    net.op_mut("alice").record_attestation(&bob_snap, 500_000);

    let arm_op = deposits_protocol::LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
    };
    net.op_mut("alice").ledger.apply_operation(&arm_op).unwrap();

    let yield_op = deposits_protocol::LedgerOperation::DisputeYield;
    net.op_mut("alice")
        .ledger
        .apply_operation(&yield_op)
        .unwrap();

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Tombstoned
    );
}

#[test]
fn normal_operations_rejected_during_dispute() {
    let mut net = setup_quorum_network();
    let user = net.create_depositor("user1", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    let dispute_op = deposits_protocol::LedgerOperation::DisputeEnter {
        last_valid_sequence: net.op("alice").ledger.state.sequence,
        reason: "test".to_string(),
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&dispute_op)
        .unwrap();

    let credit_op = deposits_protocol::LedgerOperation::InvoiceCredit {
        payment_hash: [0xCC; 32],
        deposit_id,
        amount: 50_000,
        invoice_id: "test".to_string(),
        sequence_number: 99,
    };
    let result = net.op_mut("alice").ledger.apply_operation(&credit_op);
    assert!(
        result.is_err(),
        "InvoiceCredit should be rejected during dispute"
    );
}
