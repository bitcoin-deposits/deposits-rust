//! Attack #4: Systematic signature binding check.
//!
//! For every signed object in the protocol, verify that a signature
//! from context X cannot be accepted in context Y.
//!
//! This is the general class that the cross-ledger attestation replay
//! was an instance of. Check ALL tagged-hash signing domains.

use deposits_integration_tests::adversarial::*;
use deposits_protocol::types::*;

fn make_key(seed: u8) -> (bitcoin::secp256k1::SecretKey, bitcoin::secp256k1::PublicKey) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

#[test]
fn attack_signing_domain_separation() {
    let mut log = AttackLog::new();

    let deposit_id_a = compute_deposit_id("pk(alice)");
    let deposit_id_b = compute_deposit_id("pk(bob)");
    let payment_hash = [0x01; 32];
    let withdrawal_id = [0x02; 32];
    let nonce = [0x03; 32];

    // Collect all signing message types and check pairwise that they differ
    let messages: Vec<(&str, [u8; 32])> = vec![
        (
            "invoice_lock(deposit_a)",
            deposits_protocol::invoice_lock_signing_message(&deposit_id_a, &payment_hash, 100_000),
        ),
        (
            "invoice_lock(deposit_b)",
            deposits_protocol::invoice_lock_signing_message(&deposit_id_b, &payment_hash, 100_000),
        ),
        (
            "invoice_lock(different_amount)",
            deposits_protocol::invoice_lock_signing_message(&deposit_id_a, &payment_hash, 200_000),
        ),
        (
            "withdrawal(deposit_a)",
            deposits_protocol::withdrawal_signing_message(
                &withdrawal_id,
                &deposit_id_a,
                "bcrt1q",
                100_000,
                1000,
            ),
        ),
        (
            "withdrawal(deposit_b)",
            deposits_protocol::withdrawal_signing_message(
                &withdrawal_id,
                &deposit_id_b,
                "bcrt1q",
                100_000,
                1000,
            ),
        ),
        (
            "transfer_lock",
            deposits_protocol::transfer_lock_signing_message(
                &nonce,
                &deposit_id_a,
                &deposit_id_b,
                50_000,
                500,
                "sha256(aa)",
                900_000,
            ),
        ),
        (
            "transfer_lock(reversed)",
            deposits_protocol::transfer_lock_signing_message(
                &nonce,
                &deposit_id_b,
                &deposit_id_a, // reversed
                50_000,
                500,
                "sha256(aa)",
                900_000,
            ),
        ),
    ];

    let mut steps = Vec::new();
    let mut collisions = 0;

    // Check all pairs
    for i in 0..messages.len() {
        for j in (i + 1)..messages.len() {
            let (name_i, hash_i) = &messages[i];
            let (name_j, hash_j) = &messages[j];

            if hash_i == hash_j {
                steps.push(AttackStep {
                    action: format!("Compare {} vs {}", name_i, name_j),
                    outcome: StepOutcome::Succeeded, // collision = attacker succeeds
                    detail: "COLLISION — same signing message for different contexts!".into(),
                });
                collisions += 1;
            }
        }
    }

    if collisions == 0 {
        steps.push(AttackStep {
            action: format!(
                "Check {} pairwise comparisons",
                messages.len() * (messages.len() - 1) / 2
            ),
            outcome: StepOutcome::Rejected,
            detail: "All signing messages are unique across contexts".into(),
        });
    }

    // Also check: does deposit_id appear in every signing message?
    // This is the binding — without deposit_id, signatures are cross-deposit replayable.
    let invoice_msg =
        deposits_protocol::invoice_lock_signing_message(&deposit_id_a, &payment_hash, 100_000);
    let invoice_msg_other =
        deposits_protocol::invoice_lock_signing_message(&deposit_id_b, &payment_hash, 100_000);
    let deposit_bound = invoice_msg != invoice_msg_other;

    steps.push(AttackStep {
        action: "Verify deposit_id binding in invoice_lock".into(),
        outcome: if deposit_bound {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!(
            "Different deposit_id → different message: {}",
            deposit_bound
        ),
    });

    // Check: does amount appear in the signing message?
    let amount_msg_100k =
        deposits_protocol::invoice_lock_signing_message(&deposit_id_a, &payment_hash, 100_000);
    let amount_msg_200k =
        deposits_protocol::invoice_lock_signing_message(&deposit_id_a, &payment_hash, 200_000);
    let amount_bound = amount_msg_100k != amount_msg_200k;

    steps.push(AttackStep {
        action: "Verify amount binding in invoice_lock".into(),
        outcome: if amount_bound {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!("Different amount → different message: {}", amount_bound),
    });

    // Check: are cross-operation signatures non-replayable?
    // An invoice_lock signature should not work as a withdrawal signature.
    let cross_op_distinct = invoice_msg
        != deposits_protocol::withdrawal_signing_message(
            &withdrawal_id,
            &deposit_id_a,
            "bcrt1q",
            100_000,
            1000,
        );

    steps.push(AttackStep {
        action: "Verify cross-operation binding".into(),
        outcome: if cross_op_distinct {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!("invoice_lock ≠ withdrawal: {}", cross_op_distinct),
    });

    let all_bound = collisions == 0 && deposit_bound && amount_bound && cross_op_distinct;

    log.record(AttackResult {
        name: "Systematic signature binding check".into(),
        invariant: Invariant::SignatureBinding,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: all_bound,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "{} pairwise comparisons, {} collisions. \
             deposit_id bound: {}. amount bound: {}. cross-op distinct: {}.",
            messages.len() * (messages.len() - 1) / 2,
            collisions,
            deposit_bound,
            amount_bound,
            cross_op_distinct,
        ),
        steps,
    });

    assert!(all_bound, "All signing domains must be fully separated");
}
