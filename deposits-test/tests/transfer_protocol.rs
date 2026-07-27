//! Transfer protocol: lock, complete, timeout between deposits.

use deposits_protocol::types::compute_deposit_id;
use deposits_test::*;

#[test]
fn transfer_lock_and_complete() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let sender = net.create_depositor("sender", 10);
    let receiver = net.create_depositor("receiver", 20);

    let src_id = net.op_mut("alice").open_deposit(&sender);
    let dst_id = net.op_mut("alice").open_deposit(&receiver);

    net.op_mut("alice")
        .credit_deposit(src_id, 100_000, [0xAA; 32]);

    // Lock transfer
    let transfer_nonce = [0x42; 32];
    let transfer_id = [0x43; 32];
    let amount = 30_000u64;
    let fee = 500u64;
    let completion_script = "sha256(deadbeef)";
    let timeout_height = 900_000u32;

    let proto = deposits_protocol::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: src_id,
        destination_deposit_id: dst_id,
        amount,
        fee,
        completion_script: completion_script.to_string(),
        timeout_height,
        transfer_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: deposits_protocol::DescriptorWitness::new(),
        commitment: None,
    };
    let lock_op = deposits_core::signing::sign_op(proto, &sender.secret_key)
        .expect("TransferLock signs via dep-17 preimage");
    net.op_mut("alice")
        .ledger
        .apply_operation(&lock_op)
        .unwrap();

    // Check source: balance unchanged (it's the total obligation); locked goes up.
    let src = net.op("alice").ledger.state.deposits.get(&src_id).unwrap();
    assert_eq!(src.balance, 100_000);
    assert_eq!(src.locked_balance, amount + fee);

    // Check pending transfer exists
    assert!(net
        .op("alice")
        .ledger
        .state
        .pending_transfers
        .contains_key(&transfer_id));

    // Complete the transfer
    let complete_op = deposits_protocol::LedgerOperation::TransferComplete {
        transfer_id,
        script_witness: deposits_protocol::DescriptorWitness {
            stack: vec![vec![0xDE, 0xAD, 0xBE, 0xEF]],
        },
        commitment: None,
        dest_commitment: None,
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&complete_op)
        .unwrap();

    // Source: locked balance released; balance dropped by the amount that
    // actually left (fee stays with operator as income, not tracked as obligation).
    let src = net.op("alice").ledger.state.deposits.get(&src_id).unwrap();
    assert_eq!(src.locked_balance, 0);
    assert_eq!(src.balance, 100_000 - amount);

    // Destination: received the amount (not the fee)
    let dst = net.op("alice").ledger.state.deposits.get(&dst_id).unwrap();
    assert_eq!(dst.balance, amount);

    // No pending transfers
    assert!(net.op("alice").ledger.state.pending_transfers.is_empty());
}

#[test]
fn transfer_fail_returns_funds_to_source() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let sender = net.create_depositor("sender", 10);
    let receiver = net.create_depositor("receiver", 20);

    let src_id = net.op_mut("alice").open_deposit(&sender);
    let dst_id = net.op_mut("alice").open_deposit(&receiver);

    net.op_mut("alice")
        .credit_deposit(src_id, 100_000, [0xAA; 32]);

    // Lock
    let transfer_nonce = [0x42; 32];
    let transfer_id = [0x43; 32];
    let amount = 30_000u64;
    let fee = 500u64;
    let proto = deposits_protocol::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: src_id,
        destination_deposit_id: dst_id,
        amount,
        fee,
        completion_script: "sha256(aa)".to_string(),
        timeout_height: 900_000,
        transfer_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: deposits_protocol::DescriptorWitness::new(),
        commitment: None,
    };
    let lock_op = deposits_core::signing::sign_op(proto, &sender.secret_key)
        .expect("TransferLock signs via dep-17 preimage");
    net.op_mut("alice")
        .ledger
        .apply_operation(&lock_op)
        .unwrap();

    // Fail the transfer (timeout)
    let fail_op = deposits_protocol::LedgerOperation::TransferFail {
        transfer_id,
        block_hash: [0x00; 32],
        reason: 1, // timeout
        commitment: None,
    };
    net.op_mut("alice")
        .ledger
        .apply_operation(&fail_op)
        .unwrap();

    // Source: amount + proportional fee refunded; fixed operator fee
    // (TransferFeeSchedule::default().fixed_msats = 2) stays with the operator.
    let src = net.op("alice").ledger.state.deposits.get(&src_id).unwrap();
    assert_eq!(src.balance, 100_000 - 2);
    assert_eq!(src.locked_balance, 0);

    // Destination: nothing
    let dst = net.op("alice").ledger.state.deposits.get(&dst_id).unwrap();
    assert_eq!(dst.balance, 0);
}

#[test]
fn transfer_insufficient_balance_rejected() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let sender = net.create_depositor("sender", 10);
    let receiver = net.create_depositor("receiver", 20);

    let src_id = net.op_mut("alice").open_deposit(&sender);
    let _dst_id = net.op_mut("alice").open_deposit(&receiver);

    net.op_mut("alice")
        .credit_deposit(src_id, 10_000, [0xAA; 32]);

    // Try to transfer more than balance
    let transfer_nonce = [0x42; 32];
    let transfer_id = [0x43; 32];
    let proto = deposits_protocol::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: src_id,
        destination_deposit_id: _dst_id,
        amount: 50_000,
        fee: 500,
        completion_script: "sha256(aa)".to_string(),
        timeout_height: 900_000,
        transfer_id,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: deposits_protocol::DescriptorWitness::new(),
        commitment: None,
    };
    let lock_op = deposits_core::signing::sign_op(proto, &sender.secret_key)
        .expect("TransferLock signs via dep-17 preimage");

    let result = net.op_mut("alice").ledger.apply_operation(&lock_op);
    assert!(result.is_err());
}
