//! In-process integration test for the replacement-collateral path
//! (DEP-03 §"Replacement collateral declaration").
//!
//! Verifies the wire format + state machine handle the new field
//! end-to-end: a `DisputeArmed` carrying `Some(replacement_collateral)`
//! roundtrips through TLV, applies cleanly, and lands in the disputed
//! ledger's history with the field intact. Cosigner-edge inequality
//! and on-chain UTXO checks live in unit tests for the pure verifier
//! (`deposits-node/src/node/replacement_collateral.rs`); this test
//! exercises the protocol-level integration above the verifier.

use deposits_core::messages::ReplacementCollateral;
use deposits_core::tlv::{TlvDecode, TlvEncode};
use deposits_protocol::types::DisputeState;
use deposits_protocol::LedgerOperation;
use deposits_test::*;

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

    net
}

#[test]
fn dispute_armed_with_replacement_collateral_applies_cleanly() {
    let mut net = setup_quorum_network();

    let dispute_op = LedgerOperation::DisputeEnter {
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

    let rc = ReplacementCollateral {
        txid: [0xCA; 32],
        vout: 1,
        amount: 25_000,
    };
    let arm_op = LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
        replacement_collateral: Some(rc),
    };
    // append_operation pushes a SignedLedgerUpdate onto history (unlike
    // apply_operation, which only mutates state). We need the appended
    // update's TLV bytes to verify roundtrip preservation of the new field.
    net.op_mut("alice")
        .ledger
        .append_operation(arm_op.clone())
        .expect("DisputeArmed with Some(replacement_collateral) must apply cleanly");

    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Armed
    );

    // Inspect the appended update — its embedded operation must round-trip
    // back to the same Some(rc) we set.
    let last = net.op("alice").ledger.history.last().unwrap();
    let decoded = LedgerOperation::tlv_decode(&last.message).unwrap();
    match decoded {
        LedgerOperation::DisputeArmed {
            replacement_collateral: Some(decoded_rc),
            ..
        } => {
            assert_eq!(decoded_rc.txid, rc.txid);
            assert_eq!(decoded_rc.vout, rc.vout);
            assert_eq!(decoded_rc.amount, rc.amount);
        }
        other => panic!("expected DisputeArmed with Some, got {:?}", other),
    }
}

#[test]
fn dispute_armed_legacy_none_still_applies() {
    // Asymmetric coverage check: confirm the None case (legacy senders, or
    // disputants who declined to declare) still parses and applies. RC2's
    // wire-format compatibility hinges on this.
    let mut net = setup_quorum_network();

    let dispute_op = LedgerOperation::DisputeEnter {
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

    let arm_op = LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xAA; 20],
        target_reserves: "bcrt1qtarget".to_string(),
        replacement_collateral: None,
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&arm_op)
        .expect("DisputeArmed with None must still apply (legacy compat)");
}

#[test]
fn dispute_armed_replacement_collateral_survives_fork_rebuild() {
    // A disputant's fork branch is built by replaying updates through the
    // TLV codec. The replacement_collateral declaration must survive that
    // round-trip — otherwise cosigners verifying on the fork side won't
    // see it and (correctly) refuse to sign confiscation.
    let mut net = setup_quorum_network();

    let dispute_op = LedgerOperation::DisputeEnter {
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

    let rc_orig = ReplacementCollateral {
        txid: [0xBB; 32],
        vout: 7,
        amount: 30_000,
    };
    let arm_op = LedgerOperation::DisputeArmed {
        armed_block: 800_100,
        commitment_hash: [0x11; 20],
        target_reserves: "bcrt1qfork".to_string(),
        replacement_collateral: Some(rc_orig),
    };
    net.op_mut("alice")
        .ledger
        .append_operation(arm_op.clone())
        .unwrap();

    // Take the bytes off the appended update, encode → decode again,
    // simulating what an inbound handler does when it receives the fork
    // event from Nostr.
    let last = net.op("alice").ledger.history.last().unwrap();
    let bytes = last.message.clone();
    let reencoded = LedgerOperation::tlv_decode(&bytes).unwrap().tlv_encode();
    assert_eq!(
        bytes, reencoded,
        "TLV bytes must round-trip exactly so content_hash stays stable"
    );

    let recovered = LedgerOperation::tlv_decode(&bytes).unwrap();
    match recovered {
        LedgerOperation::DisputeArmed {
            armed_block,
            commitment_hash,
            target_reserves,
            replacement_collateral: Some(rc),
        } => {
            assert_eq!(armed_block, 800_100);
            assert_eq!(commitment_hash, [0x11; 20]);
            assert_eq!(target_reserves, "bcrt1qfork");
            assert_eq!(rc.txid, rc_orig.txid);
            assert_eq!(rc.vout, rc_orig.vout);
            assert_eq!(rc.amount, rc_orig.amount);
        }
        other => panic!("expected DisputeArmed Some(rc), got {:?}", other),
    }
}

#[test]
fn dispute_armed_partial_amount_is_distinct() {
    // A disputant CAN declare an `amount` smaller than the UTXO's value
    // (taking change). The codec must preserve the declared `amount`
    // verbatim — cosigners check it against the on-chain UTXO value
    // separately, but the on-the-wire commitment is what they enforce
    // the inequality against.
    let mut net = setup_quorum_network();

    let dispute_op = LedgerOperation::DisputeEnter {
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

    // Two arms differing ONLY in declared amount — they must produce
    // different content_hashes (so cosigners can't be tricked by amount
    // tampering) and decode back to their respective amounts.
    let mk_arm = |amount: u64| LedgerOperation::DisputeArmed {
        armed_block: 800_000,
        commitment_hash: [0xCD; 20],
        target_reserves: "bcrt1qcommit".to_string(),
        replacement_collateral: Some(ReplacementCollateral {
            txid: [0xDE; 32],
            vout: 0,
            amount,
        }),
    };
    let bytes_30k = mk_arm(30_000).tlv_encode();
    let bytes_25k = mk_arm(25_000).tlv_encode();
    assert_ne!(
        bytes_30k, bytes_25k,
        "different declared amounts MUST produce different TLV bytes"
    );
}

#[test]
fn replacement_collateral_struct_eq_and_copy() {
    // Surface check that ReplacementCollateral is Copy + Eq — the cosign
    // verifier and the multi-input claim-TX builder both move it across
    // contexts assuming this. Catches accidental loss of those derives.
    let a = ReplacementCollateral {
        txid: [1; 32],
        vout: 0,
        amount: 10_000,
    };
    let b = a; // Copy
    assert_eq!(a, b);
    assert_eq!(
        a,
        ReplacementCollateral {
            txid: [1; 32],
            vout: 0,
            amount: 10_000,
        }
    );
}
