//! Quorum formation: add members, begin quorum.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::ledger::Ledger;
use deposits_test::*;
use deposits_protocol::types::QuorumState;

#[test]
fn add_quorum_member_appears_in_next_members() {
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);
    let bob_pk = bob_snap.public_key;

    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);

    assert!(net
        .op("alice")
        .ledger
        .state
        .next_quorum_members
        .iter()
        .any(|m| m.pubkey == bob_pk));
    assert_eq!(
        net.op("alice").ledger.state.quorum_state,
        QuorumState::PreQuorum
    );
}

#[test]
fn quorum_begin_promotes_members() {
    let mut net = TestNetwork::new(&["alice", "bob", "charlie"], 1_000_000);

    // Snapshot bob and charlie before borrowing net mutably
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

    assert_eq!(net.op("alice").ledger.state.next_quorum_members.len(), 2);
    assert!(net.op("alice").ledger.state.quorum_members.is_empty());

    // Begin quorum
    net.op_mut("alice").begin_quorum(1_000_000);

    assert!(net.op("alice").ledger.state.next_quorum_members.is_empty());
    assert_eq!(net.op("alice").ledger.state.quorum_members.len(), 2);
    assert_eq!(
        net.op("alice").ledger.state.quorum_state,
        QuorumState::Active
    );
}

#[test]
fn full_quorum_setup_three_operators() {
    let mut net = TestNetwork::new(&["alice", "bob", "charlie"], 1_000_000);

    // Snapshot all operators
    let ops: Vec<(String, SecretKey, PublicKey, String)> = net
        .operators
        .iter()
        .map(|o| {
            (
                o.name.clone(),
                o.secret_key,
                o.public_key,
                hex::encode(o.ledger.state.ledger_id),
            )
        })
        .collect();

    // Alice adds Bob and Charlie as quorum members
    for (name, sk, pk, lid) in &ops {
        if name == "alice" {
            continue;
        }
        let member = Operator {
            name: name.clone(),
            secret_key: *sk,
            public_key: *pk,
            ledger: Ledger::new_as_operator(*pk, format!("bcrt1q{}reserves", name), 0),
        };
        net.op_mut("alice").add_quorum_member(&member, lid);
    }

    net.op_mut("alice").begin_quorum(1_000_000);

    // Verify full quorum state
    let state = &net.op("alice").ledger.state;
    assert_eq!(state.quorum_state, QuorumState::Active);
    assert_eq!(state.quorum_members.len(), 2);
    assert!(state.has_sufficient_reserves());
}
