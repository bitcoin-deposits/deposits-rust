//! Conformance detection: watcher detects operator violations.

use deposits_protocol::types::ConformanceViolation;
use deposits_test::*;

#[test]
fn watcher_detects_over_reserve_credit() {
    let mut net = TestNetwork::new(&["alice"], 500_000); // 500k reserves
    let mut watcher = net.create_watcher("alice");
    let user = net.create_depositor("user1", 10);

    let deposit_id = net.op_mut("alice").open_deposit(&user);

    // Credit within reserves — should be conforming
    net.op_mut("alice")
        .credit_deposit(deposit_id, 400_000, [0xAA; 32]);

    let violations = net.op("alice").sync_to_checked(&mut watcher);
    assert!(violations.is_empty(), "within reserves: {:?}", violations);

    // Credit exceeding reserves — watcher should detect
    net.op_mut("alice")
        .credit_deposit(deposit_id, 200_000, [0xBB; 32]);

    // Sync only the latest operation
    let last_update = net.op("alice").ledger.history.last().unwrap();
    if let Ok(op) = deposits_protocol::LedgerOperation::tlv_decode(&last_update.message) {
        let violations = watcher
            .apply_and_check(&op, last_update.block_height)
            .unwrap();
        watcher.state.sequence = last_update.sequence_number;
        watcher.state.chain_tip_hash = last_update.chain_hash();

        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ConformanceViolation::InsufficientReserves { .. }
        ));
    }

    // Watcher still tracks the state (even though non-conforming)
    assert_eq!(
        watcher.state.deposits.get(&deposit_id).unwrap().balance,
        600_000
    );
}

#[test]
fn watcher_sees_identical_state_when_conforming() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let mut watcher = net.create_watcher("alice");
    let user = net.create_depositor("user1", 10);

    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 200_000, [0xBB; 32]);

    // Sync watcher
    net.op("alice").sync_to(&mut watcher);

    // States should match
    assert_eq!(
        watcher.state.total_deposit_balance(),
        net.op("alice").ledger.state.total_deposit_balance()
    );
    assert_eq!(
        watcher.state.sequence,
        net.op("alice").ledger.state.sequence
    );
}

#[test]
fn conforming_operations_produce_no_violations() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let mut watcher = net.create_watcher("alice");
    let user = net.create_depositor("user1", 10);

    // Open deposit, credit within reserves, do multiple operations
    net.op_mut("alice").open_deposit(&user);
    let user2 = net.create_depositor("user2", 20);
    net.op_mut("alice").open_deposit(&user2);

    let did1 = deposits_protocol::types::compute_deposit_id(&format!(
        "pk({})",
        hex::encode(user.public_key.serialize())
    ));
    net.op_mut("alice")
        .credit_deposit(did1, 300_000, [0xAA; 32]);

    let violations = net.op("alice").sync_to_checked(&mut watcher);
    assert!(
        violations.is_empty(),
        "expected no violations: {:?}",
        violations
    );
}

#[test]
fn watcher_detects_bad_invoice_witness() {
    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let mut watcher = net.create_watcher("alice");
    let user = net.create_depositor("user1", 10);

    let deposit_id = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice")
        .credit_deposit(deposit_id, 100_000, [0xAA; 32]);

    // Sync everything so far (conforming)
    net.op("alice").sync_to(&mut watcher);

    // Now apply an InvoiceLock with a BAD witness directly to operator's ledger
    // (bypassing the signed witness helper)
    let payment_id = [0x01; 32];
    let bad_op = deposits_protocol::LedgerOperation::InvoiceLock {
        deposit_id,
        amount: 30_000,
        payment_id,
        sequence_number: net.op("alice").ledger.state.sequence + 1,
        nonce: 0,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: deposits_protocol::DescriptorWitness {
            stack: vec![vec![0xFF; 64]], // garbage signature
        },
        commitment: None,
    };
    net.op_mut("alice").ledger.append_operation(bad_op).unwrap();

    // Sync the bad operation to watcher with conformance checking
    let last_update = net.op("alice").ledger.history.last().unwrap();
    if let Ok(op) = deposits_protocol::LedgerOperation::tlv_decode(&last_update.message) {
        let violations = watcher
            .apply_and_check(&op, last_update.block_height)
            .unwrap();
        watcher.state.sequence = last_update.sequence_number;
        watcher.state.chain_tip_hash = last_update.chain_hash();

        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ConformanceViolation::InvalidWitness {
                operation: "InvoiceLock",
                ..
            }
        ));
    }
}

use deposits_protocol::TlvDecode;
