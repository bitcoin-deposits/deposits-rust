//! End-to-end deposit lifecycle: open, credit, lock, fulfill, close.

use deposits_test::*;
use deposits_protocol::types::compute_deposit_id;

#[test]
fn deposit_open_credit_close() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("user1", 10);

    let deposit_id = net.op_mut("alice").open_deposit(&user);

    // Verify deposit exists with zero balance
    let deposit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap();
    assert_eq!(deposit.balance, 0);

    // Credit via invoice
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    let deposit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap();
    assert_eq!(deposit.balance, 100_000);

    // Credit again with different payment hash
    net.op_mut("alice")
        .credit_deposit(deposit_id, 50_000, [0xBB; 32]);

    let deposit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap();
    assert_eq!(deposit.balance, 150_000);
}

#[test]
fn deposit_duplicate_credit_rejected() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("user1", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);

    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Same payment hash should fail
    let op = deposits_protocol::LedgerOperation::InvoiceCredit {
        payment_hash: [0xAA; 32],
        deposit_id,
        amount: 100_000,
        invoice_id: "dup".to_string(),
        sequence_number: 99,
    };
    let result = net.op_mut("alice").ledger.apply_operation(&op);
    assert!(result.is_err());
}

#[test]
fn deposit_lock_and_fulfill_invoice() {
    use bitcoin::hashes::{sha256, Hash};

    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("user1", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);

    // Credit 100k
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Use preimage-derived payment_id from the start
    let preimage = [0x42; 32];
    let payment_id = sha256::Hash::hash(&preimage).to_byte_array();

    // Lock 30k
    net.op_mut("alice")
        .lock_invoice(&user, deposit_id, 30_000, payment_id);

    let deposit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap();
    assert_eq!(deposit.balance, 100_000, "total balance unchanged by lock");
    assert_eq!(deposit.locked_balance, 30_000);
    assert_eq!(
        deposit.available_balance(),
        70_000,
        "available = balance - locked"
    );

    // Fulfill with preimage
    net.op_mut("alice")
        .fulfill_invoice(&user, deposit_id, 30_000, payment_id, preimage);

    let deposit = net
        .op("alice")
        .ledger
        .state
        .deposits
        .get(&deposit_id)
        .unwrap();
    assert_eq!(
        deposit.balance, 70_000,
        "balance reduced after fulfill (locked consumed)"
    );
    assert_eq!(deposit.locked_balance, 0, "locked released after fulfill");
}

#[test]
fn deposit_close_requires_zero_balance() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("user1", 10);
    let deposit_id = net.op_mut("alice").open_deposit(&user);

    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Close should fail with non-zero balance
    let close_op = deposits_protocol::LedgerOperation::DepositClose { deposit_id };
    let result = net.op_mut("alice").ledger.apply_operation(&close_op);
    assert!(result.is_err());
}

#[test]
fn multiple_deposits_independent_balances() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user1 = net.create_depositor("user1", 10);
    let user2 = net.create_depositor("user2", 20);

    let did1 = net.op_mut("alice").open_deposit(&user1);
    let did2 = net.op_mut("alice").open_deposit(&user2);

    net.op_mut("alice")
        .credit_deposit(did1, 100_000, [0xAA; 32]);
    net.op_mut("alice")
        .credit_deposit(did2, 200_000, [0xBB; 32]);

    assert_eq!(
        net.op("alice")
            .ledger
            .state
            .deposits
            .get(&did1)
            .unwrap()
            .balance,
        100_000
    );
    assert_eq!(
        net.op("alice")
            .ledger
            .state
            .deposits
            .get(&did2)
            .unwrap()
            .balance,
        200_000
    );
    assert_eq!(
        net.op("alice").ledger.state.total_deposit_balance(),
        300_000
    );
}

#[test]
fn hash_chain_advances_with_each_operation() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("user1", 10);

    let hash_after_open = net.op("alice").ledger.state.chain_tip_hash;
    let seq_after_open = net.op("alice").ledger.state.sequence;

    let deposit_id = net.op_mut("alice").open_deposit(&user);

    let hash_after_deposit = net.op("alice").ledger.state.chain_tip_hash;
    assert_ne!(hash_after_open, hash_after_deposit);
    assert_eq!(net.op("alice").ledger.state.sequence, seq_after_open + 1);

    net.op_mut("alice")
        .credit_deposit(deposit_id, 50_000, [0xAA; 32]);

    let hash_after_credit = net.op("alice").ledger.state.chain_tip_hash;
    assert_ne!(hash_after_deposit, hash_after_credit);
}
