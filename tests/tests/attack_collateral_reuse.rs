//! Collateral reuse attack: can the same collateral back multiple ledgers
//! and be insufficient when they all fail simultaneously?

use deposits_core::ledger::Ledger;
use deposits_integration_tests::adversarial::*;
use deposits_integration_tests::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::*;

#[test]
fn attack_collateral_reuse_across_ledgers() {
    let mut log = AttackLog::new();

    // Scenario: Bob has a collateral deposit with 500k sats.
    // Bob backs 3 of Alice's ledgers (the MAX_COLLATERAL_LOCKS cap).
    // Each ledger has deposits totaling 300k (within reserves).
    //
    // If Alice goes non-conforming on ALL 3 ledgers simultaneously:
    // - Total deposits at risk: 3 × 300k = 900k
    // - Bob's collateral: 500k
    // - Shortfall: 400k sats that depositors can't recover from collateral
    //
    // The protocol allows this because:
    // 1. Each individual ledger's collateral check passes (500k > 300k)
    // 2. But the SAME 500k is counted 3 times

    // Create Alice with 3 ledgers (different reserves keys)
    let mut net = TestNetwork::new(&["alice", "bob"], 1_000_000);

    // Bob's collateral deposit
    let bob_snap = Operator {
        name: "bob".into(),
        secret_key: net.op("bob").secret_key,
        public_key: net.op("bob").public_key,
        ledger: net.op("bob").ledger.clone(),
    };
    let bob_lid = hex::encode(bob_snap.ledger.state.ledger_id);

    // Set up quorum on Alice's ledger with Bob as member
    net.op_mut("alice").add_quorum_member(&bob_snap, &bob_lid);
    net.op_mut("alice").begin_quorum(1_000_000);

    // Bob attests 500k collateral
    net.op_mut("alice").record_attestation(&bob_snap, 500_000);

    // Add deposits on Alice's ledger
    let u1 = net.create_depositor("u1", 10);
    let u2 = net.create_depositor("u2", 20);
    let u3 = net.create_depositor("u3", 30);
    let d1 = net.op_mut("alice").open_deposit(&u1);
    let d2 = net.op_mut("alice").open_deposit(&u2);
    let d3 = net.op_mut("alice").open_deposit(&u3);
    net.op_mut("alice").credit_deposit(d1, 300_000, [0x01; 32]);
    net.op_mut("alice").credit_deposit(d2, 300_000, [0x02; 32]);
    net.op_mut("alice").credit_deposit(d3, 300_000, [0x03; 32]);

    let total_deposits = net.op("alice").ledger.state.total_deposit_balance();
    let total_collateral = net.op("alice").ledger.state.total_collateral();
    let reserves = net.op("alice").ledger.state.reserves_amount;

    // Per-ledger view: 500k collateral vs 900k deposits
    // The collateral is technically for ONE ledger here, but the same
    // collateral deposit on Bob's ledger could be locked for up to 3 ledgers.

    // Now test the cap: try to lock Bob's collateral for a second ledger_id
    // (simulating Bob backing a second operator's ledger with same collateral)
    let bob_collateral_desc = format!("pk({})", hex::encode(bob_snap.public_key.serialize()));
    let bob_collateral_id = compute_deposit_id(&bob_collateral_desc);

    // On Bob's ledger, create a collateral deposit
    net.op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::DepositOpen {
            deposit_id: bob_collateral_id,
            descriptor: bob_collateral_desc.clone(),
            fees: Some(FeeStructure::default()),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            is_collateral: true,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();

    // Credit it
    net.op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xDD; 32],
            deposit_id: bob_collateral_id,
            amount: 500_000,
            invoice_id: "collateral".into(),
            sequence_number: 1,
        })
        .unwrap();

    // Lock for ledger 1
    let bob_pk = net.op("bob").public_key;
    net.op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::CollateralLock {
            deposit_id: bob_collateral_id,
            amount: 500_000,
            lock_until_block: 900_000,
            operator_id: bob_pk,
            witness: DescriptorWitness {
                stack: vec![vec![0xFF; 64]],
            },
            for_ledger_id: "ledger_alice_1".into(),
        })
        .unwrap();

    // Lock for ledger 2
    net.op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::CollateralLock {
            deposit_id: bob_collateral_id,
            amount: 500_000,
            lock_until_block: 900_000,
            operator_id: bob_pk,
            witness: DescriptorWitness {
                stack: vec![vec![0xFF; 64]],
            },
            for_ledger_id: "ledger_alice_2".into(),
        })
        .unwrap();

    // Lock for ledger 3
    net.op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::CollateralLock {
            deposit_id: bob_collateral_id,
            amount: 500_000,
            lock_until_block: 900_000,
            operator_id: bob_pk,
            witness: DescriptorWitness {
                stack: vec![vec![0xFF; 64]],
            },
            for_ledger_id: "ledger_alice_3".into(),
        })
        .unwrap();

    // Try to lock for ledger 4 — should fail (MAX_COLLATERAL_LOCKS = 3)
    let fourth_lock = net
        .op_mut("bob")
        .ledger
        .apply_operation(&LedgerOperation::CollateralLock {
            deposit_id: bob_collateral_id,
            amount: 500_000,
            lock_until_block: 900_000,
            operator_id: bob_pk,
            witness: DescriptorWitness {
                stack: vec![vec![0xFF; 64]],
            },
            for_ledger_id: "ledger_alice_4".into(),
        });

    let cap_enforced = fourth_lock.is_err();

    // Check the actual collateral state
    let bob_deposit = net
        .op("bob")
        .ledger
        .state
        .deposits
        .get(&bob_collateral_id)
        .unwrap();

    // The TOTAL collateral_lock_amount is the SUM of all per-ledger locks
    // This is where the double-counting happens: 500k × 3 = 1.5M locked,
    // but the deposit only HAS 500k balance.
    let total_locked = bob_deposit.collateral_lock_amount;
    let actual_balance = bob_deposit.balance;
    let overcommitted = total_locked > actual_balance;

    // The overcommitment is INTENDED. The collateral is a deterrence
    // mechanism (operator's skin in the game), not the primary recovery
    // mechanism. Reserves are the primary backing — they require quorum
    // signatures to spend and are NOT under operator control.
    //
    // If an operator misbehaves, the quorum confiscates RESERVES (not collateral).
    // Collateral is the cost the attacker bears — it doesn't need to equal
    // total deposits because reserves already cover that.
    //
    // The security argument is:
    //   reserves (1M) >= total_deposits (900k)     ← depositors are made whole
    //   collateral (500k) > 0                      ← attacker loses something
    //   collateral shared across 3 ledgers         ← attacker's cost per ledger

    log.record(AttackResult {
        name: "Collateral reuse across 3 ledgers (by design)".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 500_000,
        extraction_sats: 0, // no extraction — reserves cover deposits
        blocked: true,      // reserves are the defense, not collateral alone
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        steps: vec![
            AttackStep {
                action: "Lock collateral for ledger 1".into(),
                outcome: StepOutcome::Succeeded,
                detail: "500k locked for ledger_alice_1".into(),
            },
            AttackStep {
                action: "Lock collateral for ledger 2".into(),
                outcome: StepOutcome::Succeeded,
                detail: "500k locked for ledger_alice_2 (same deposit, by design)".into(),
            },
            AttackStep {
                action: "Lock collateral for ledger 3".into(),
                outcome: StepOutcome::Succeeded,
                detail: "500k locked for ledger_alice_3 (same deposit, by design)".into(),
            },
            AttackStep {
                action: "Lock collateral for ledger 4".into(),
                outcome: if cap_enforced {
                    StepOutcome::Rejected
                } else {
                    StepOutcome::Succeeded
                },
                detail: format!("Cap of 3 enforced: {}", cap_enforced),
            },
            AttackStep {
                action: "Verify reserves cover deposits".into(),
                outcome: if reserves >= total_deposits {
                    StepOutcome::Rejected
                } else {
                    StepOutcome::Succeeded
                },
                detail: format!(
                    "reserves={} >= deposits={}: depositors made whole via quorum confiscation",
                    reserves, total_deposits
                ),
            },
        ],
        notes: format!(
            "Collateral reuse across ledgers is by design. Reserves ({} sats) \
             are the primary backing and require quorum to spend. Collateral \
             ({} sats, shared across {} ledgers) is the attacker's cost, not \
             the recovery fund. Cap of {} ledgers per deposit enforced.",
            reserves,
            actual_balance,
            bob_deposit.collateral_locks.len(),
            deposits_protocol::types::MAX_COLLATERAL_LOCKS,
        ),
    });

    assert!(cap_enforced, "4th ledger lock must be rejected");
    assert!(
        reserves >= total_deposits,
        "Reserves must cover total deposits (the real defense)"
    );
}
