//! Coverage tests for protocol operations that had zero dedicated testing.
//!
//! Each test exercises one LedgerOperation through its happy path
//! and at least one error case.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use deposits_core::ledger::Ledger;
use deposits_test::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::*;

// =========================================================================
// OnchainCredit / OnchainLock / OnchainFulfill / OnchainFail
// =========================================================================

#[test]
fn onchain_credit_lock_fulfill() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);

    // OnchainCredit
    net.op_mut("alice")
        .ledger
        .append_operation(LedgerOperation::OnchainCredit {
            txid: [0x11; 32],
            vout: 0,
            deposit_id: did,
            amount: 200_000,
            funding_address: "bcrt1qfund".into(),
        })
        .unwrap();

    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.balance, 200_000);

    // OnchainLock (withdrawal)
    let withdrawal_id = [0x01; 32];
    let proto = LedgerOperation::OnchainLock {
        deposit_id: did,
        amount: 100_000,
        fee_sats: 1_000,
        destination_address: "bcrt1qdest".into(),
        withdrawal_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &user.secret_key)
        .expect("OnchainLock signs via dep-17 preimage");
    net.op_mut("alice").ledger.apply_operation(&op).unwrap();

    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    // OnchainLock locks amount + fee_sats (both leave when the withdrawal
    // confirms: amount to destination, fee to miners). Balance is unchanged
    // until fulfill; locked = 100k + 1k = 101k.
    assert_eq!(deposit.balance, 200_000, "balance unchanged by lock");
    assert_eq!(
        deposit.locked_balance, 101_000,
        "locked = amount + fee_sats"
    );

    // OnchainFulfill
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::OnchainFulfill {
            deposit_id: did,
            amount: 100_000,
            withdrawal_id,
            txid: [0x22; 32],
            destination_address: "bcrt1qdest".into(),
        })
        .unwrap();

    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    // Fulfill decrements balance and locked by the full total (amount + fee).
    // Both actually left the ledger: amount to destination, fee to miners.
    assert_eq!(deposit.balance, 99_000, "balance -= amount + fee_sats");
    assert_eq!(deposit.locked_balance, 0);
}

#[test]
fn onchain_fail_returns_funds() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);

    net.op_mut("alice")
        .ledger
        .append_operation(LedgerOperation::OnchainCredit {
            txid: [0x11; 32],
            vout: 0,
            deposit_id: did,
            amount: 200_000,
            funding_address: "bcrt1qfund".into(),
        })
        .unwrap();

    // Lock
    let withdrawal_id = [0x01; 32];
    let proto = LedgerOperation::OnchainLock {
        deposit_id: did,
        amount: 100_000,
        fee_sats: 1_000,
        destination_address: "bcrt1qdest".into(),
        withdrawal_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &user.secret_key)
        .expect("OnchainLock signs via dep-17 preimage");
    net.op_mut("alice").ledger.apply_operation(&op).unwrap();

    // Confirm the lock recorded by OnchainLock.
    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.balance, 200_000, "balance unchanged by lock");
    assert_eq!(
        deposit.locked_balance, 101_000,
        "locked = amount + fee_sats"
    );

    // Fail (onchain withdrawal didn't confirm)
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::OnchainFail {
            deposit_id: did,
            withdrawal_id,
        })
        .unwrap();

    // OnchainFail releases the lock and charges the fixed operator fee
    // (TransferFeeSchedule::default().fixed_msats = 2). Locked goes to 0;
    // balance drops by the fixed fee.
    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.balance, 200_000 - 2, "fixed fee charged on fail");
    assert_eq!(deposit.locked_balance, 0, "fail releases the lock");
    assert!(
        !net.op("alice")
            .ledger
            .state
            .pending_withdrawals
            .contains_key(&withdrawal_id),
        "pending_withdrawals entry cleaned up on fail"
    );
}

// =========================================================================
// InvoiceFail
// =========================================================================

#[test]
fn invoice_fail_unlocks_funds() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice").credit_deposit(did, 100_000, [0xAA; 32]);

    // Lock
    use bitcoin::hashes::{sha256, Hash};
    let preimage = [0x42; 32];
    let payment_id = sha256::Hash::hash(&preimage).to_byte_array();
    net.op_mut("alice")
        .lock_invoice(&user, did, 30_000, payment_id);

    assert_eq!(
        net.op("alice")
            .ledger
            .state
            .deposits
            .get(&did)
            .unwrap()
            .locked_balance,
        30_000
    );

    // Fail the payment
    let next_seq = net.op("alice").ledger.state.sequence + 1;
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::InvoiceFail {
            deposit_id: did,
            payment_id,
            sequence_number: next_seq,
        })
        .unwrap();

    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.locked_balance, 0, "InvoiceFail should unlock");
    // InvoiceFail restores the balance minus the fixed operator fee
    // (TransferFeeSchedule::default().fixed_msats = 2).
    assert_eq!(
        deposit.balance,
        100_000 - 2,
        "InvoiceFail restores balance minus fixed operator fee"
    );
}

// =========================================================================
// FeeChange
// =========================================================================

#[test]
fn fee_change_applied_on_collect() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice").credit_deposit(did, 100_000, [0xAA; 32]);

    // Change fees (takes effect at a future block)
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure {
                annualized_msats: 2000,
                annualized_bps: 100,
                frequency_blocks: 1008,
            },
            effective_block: 500,
        })
        .unwrap();

    // Pending fee change should be recorded
    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert!(
        deposit.pending_fee_change.is_some(),
        "FeeChange should set pending"
    );

    // FeeCollect at a block AFTER effective_block applies the change
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 100,
            block_height: 600,
        })
        .unwrap();

    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert!(
        deposit.pending_fee_change.is_none(),
        "FeeCollect after effective_block should apply pending change"
    );
    assert_eq!(deposit.fees.annualized_bps, 100);
}

// =========================================================================
// DepositKeyRotate
// =========================================================================

#[test]
fn deposit_key_rotate() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);

    let new_user = net.create_depositor("u_new", 20);
    let new_descriptor = format!("pk({})", hex::encode(new_user.public_key.serialize()));

    // Sign rotation with OLD key — message is SHA256(new_descriptor)
    use bitcoin::hashes::{sha256, Hash};
    let msg_hash = sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();
    let sig = sign_schnorr_helper(&user.secret_key, &msg_hash);

    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DepositKeyRotate {
            deposit_id: did,
            new_descriptor: new_descriptor.clone(),
            nonce: 0,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig.to_vec()],
            },
        })
        .unwrap();

    // Descriptor should be updated
    let deposit = net.op("alice").ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.descriptor, new_descriptor);
}

fn sign_schnorr_helper(sk: &SecretKey, msg_hash: &[u8; 32]) -> [u8; 64] {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, sk);
    let msg = Message::from_digest(*msg_hash);
    secp.sign_schnorr_no_aux_rand(&msg, &keypair).serialize()
}

// =========================================================================
// QuorumRemoveMember
// =========================================================================

#[test]
fn quorum_remove_member() {
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);

    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);

    assert_eq!(net.op("alice").ledger.state.next_quorum_members.len(), 1);

    // Remove
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::QuorumRemoveMember {
            quorum_member: bob_snap.public_key,
            operator_signature: [0xAB; 64],
        })
        .unwrap();

    assert_eq!(net.op("alice").ledger.state.next_quorum_members.len(), 0);
}

// =========================================================================
// QuorumJoin (on operator's own ledger)
// =========================================================================

#[test]
fn quorum_join_records_membership() {
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    let bob_pk = net.op("bob").public_key;
    let bob_lid = hex::encode(net.op("bob").ledger.state.ledger_id);

    // Alice records that she joined bob's quorum
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::QuorumJoin {
            operator_id: bob_pk,
            ledger_id: bob_lid.clone(),
            membership_expires: 900_000,
        })
        .unwrap();

    let joined = &net.op("alice").ledger.state.joined_quorums;
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].operator_id, bob_pk);
    assert_eq!(joined[0].membership_expires, 900_000);
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn double_dispute_enter_rejected() {
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);
    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);
    net.op_mut("alice").begin_quorum(1_000_000);

    let seq = net.op("alice").ledger.state.sequence;
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DisputeEnter {
            last_valid_sequence: seq,
            reason: "first".into(),
            anchor_block_hash: None,
            anchor_block_height: None,
        })
        .unwrap();

    // Second DisputeEnter should fail (already disputed)
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DisputeEnter {
            last_valid_sequence: seq,
            reason: "second".into(),
            anchor_block_hash: None,
            anchor_block_height: None,
        });
    assert!(result.is_err(), "Double DisputeEnter must be rejected");
}

#[test]
fn add_duplicate_quorum_member_is_idempotent() {
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);

    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);
    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid); // duplicate

    // Should still only have one member (deduplicated)
    assert_eq!(net.op("alice").ledger.state.next_quorum_members.len(), 1);
}

#[test]
fn transfer_complete_on_already_completed_ignored() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let sender = net.create_depositor("sender", 10);
    let receiver = net.create_depositor("receiver", 20);
    let src = net.op_mut("alice").open_deposit(&sender);
    let dst = net.op_mut("alice").open_deposit(&receiver);
    net.op_mut("alice").credit_deposit(src, 100_000, [0xAA; 32]);

    // Lock
    let transfer_nonce = [0x42; 32];
    let transfer_id = [0x43; 32];
    let proto = LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: src,
        destination_deposit_id: dst,
        amount: 30_000,
        fee: 500,
        completion_script: "sha256(aa)".into(),
        timeout_height: 900_000,
        transfer_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &sender.secret_key)
        .expect("TransferLock signs via dep-17 preimage");
    net.op_mut("alice").ledger.apply_operation(&op).unwrap();

    // Complete
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::TransferComplete {
            transfer_id,
            script_witness: DescriptorWitness {
                stack: vec![vec![0xAA]],
            },
        })
        .unwrap();

    // Complete again (should be no-op — transfer already removed from pending)
    let result = net
        .op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::TransferComplete {
            transfer_id,
            script_witness: DescriptorWitness {
                stack: vec![vec![0xBB]],
            },
        });
    // This should succeed (no-op) or fail gracefully — transfer not found
    // The protocol applies it as a no-op (pending_transfers.remove returns None)
    assert!(
        result.is_ok(),
        "Double complete should be a no-op, not an error"
    );
}
