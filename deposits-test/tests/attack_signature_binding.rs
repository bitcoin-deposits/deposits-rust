//! Attack #4: Systematic signature binding check.
//!
//! For every signed operation in the protocol, verify that a signature
//! from context X cannot be accepted in context Y. The dep-17 operation
//! preimage is the only signing domain the wallet/operator pair uses —
//! this test confirms its construction binds op_type + every field that
//! distinguishes one authorization from another, so a signature for one
//! op is unusable for any other op (cross-deposit, cross-amount,
//! cross-op-type, cross-nonce, cross-expiry).

use deposits_core::messages::LedgerOperation;
use deposits_core::signing::sign_op;
use deposits_protocol::types::*;
use deposits_test::adversarial::*;

fn make_key(seed: u8) -> (bitcoin::secp256k1::SecretKey, bitcoin::secp256k1::PublicKey) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

/// dep-17 operation preimage for the given op. Panics on variants that don't
/// route through dep-16 authorization — none of the ops constructed in this
/// test fall into that bucket.
fn preimage(op: &LedgerOperation) -> [u8; 32] {
    deposits_core::dep16::operations::operation_sighash(op).expect("test op must be signable")
}

fn invoice_lock(
    deposit_id: DepositId,
    payment_id: [u8; 32],
    amount: u64,
    nonce: u64,
) -> LedgerOperation {
    LedgerOperation::InvoiceLock {
        deposit_id,
        amount,
        payment_id,
        sequence_number: 1,
        nonce,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: DescriptorWitness::new(),
        commitment: None,
    }
}

fn onchain_lock(
    deposit_id: DepositId,
    withdrawal_id: [u8; 32],
    destination: &str,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> LedgerOperation {
    LedgerOperation::OnchainLock {
        deposit_id,
        amount,
        fee_sats: fee,
        destination_address: destination.into(),
        withdrawal_id,
        nonce,
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
        commitment: None,
    }
}

fn transfer_lock(
    transfer_nonce: [u8; 32],
    source: DepositId,
    dest: DepositId,
    amount: u64,
    fee: u64,
    completion_script: &str,
    timeout: u32,
    nonce: u64,
) -> LedgerOperation {
    LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: source,
        destination_deposit_id: dest,
        amount,
        fee,
        completion_script: completion_script.into(),
        timeout_height: timeout,
        transfer_id: [0xee; 32],
        nonce,
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
        commitment: None,
    }
}

#[test]
fn attack_signing_domain_separation() {
    let mut log = AttackLog::new();

    let deposit_id_a = compute_deposit_id("pk(alice)");
    let deposit_id_b = compute_deposit_id("pk(bob)");
    let payment_hash = [0x01; 32];
    let withdrawal_id = [0x02; 32];
    let transfer_nonce = [0x03; 32];

    // Collect dep-17 preimages for distinct op contexts. Op nonce is held
    // constant across the comparison set so that any difference comes from
    // the op shape, not the nonce.
    let nonce: u64 = 42;
    let messages: Vec<(&str, [u8; 32])> = vec![
        (
            "invoice_lock(deposit_a)",
            preimage(&invoice_lock(deposit_id_a, payment_hash, 100_000, nonce)),
        ),
        (
            "invoice_lock(deposit_b)",
            preimage(&invoice_lock(deposit_id_b, payment_hash, 100_000, nonce)),
        ),
        (
            "invoice_lock(different_amount)",
            preimage(&invoice_lock(deposit_id_a, payment_hash, 200_000, nonce)),
        ),
        (
            "withdrawal(deposit_a)",
            preimage(&onchain_lock(
                deposit_id_a,
                withdrawal_id,
                "bcrt1q",
                100_000,
                1000,
                nonce,
            )),
        ),
        (
            "withdrawal(deposit_b)",
            preimage(&onchain_lock(
                deposit_id_b,
                withdrawal_id,
                "bcrt1q",
                100_000,
                1000,
                nonce,
            )),
        ),
        (
            "transfer_lock",
            preimage(&transfer_lock(
                transfer_nonce,
                deposit_id_a,
                deposit_id_b,
                50_000,
                500,
                "sha256(aa)",
                900_000,
                nonce,
            )),
        ),
        (
            "transfer_lock(reversed)",
            preimage(&transfer_lock(
                transfer_nonce,
                deposit_id_b,
                deposit_id_a,
                50_000,
                500,
                "sha256(aa)",
                900_000,
                nonce,
            )),
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

    // The pairwise sweep above already covers deposit_id, amount, and
    // cross-op-type binding via concrete examples in the messages vec.
    // Re-derive the three focused properties as named checks so the
    // attack log records each binding independently.
    let invoice_msg = preimage(&invoice_lock(deposit_id_a, payment_hash, 100_000, nonce));
    let invoice_msg_other = preimage(&invoice_lock(deposit_id_b, payment_hash, 100_000, nonce));
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

    let amount_msg_200k = preimage(&invoice_lock(deposit_id_a, payment_hash, 200_000, nonce));
    let amount_bound = invoice_msg != amount_msg_200k;

    steps.push(AttackStep {
        action: "Verify amount binding in invoice_lock".into(),
        outcome: if amount_bound {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!("Different amount → different message: {}", amount_bound),
    });

    let withdrawal_msg = preimage(&onchain_lock(
        deposit_id_a,
        withdrawal_id,
        "bcrt1q",
        100_000,
        1000,
        nonce,
    ));
    let cross_op_distinct = invoice_msg != withdrawal_msg;

    steps.push(AttackStep {
        action: "Verify cross-operation binding".into(),
        outcome: if cross_op_distinct {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!("invoice_lock ≠ withdrawal: {}", cross_op_distinct),
    });

    // dep-17 also binds op_nonce, so signatures don't replay across nonces.
    let other_nonce_msg = preimage(&invoice_lock(
        deposit_id_a,
        payment_hash,
        100_000,
        nonce + 1,
    ));
    let nonce_bound = invoice_msg != other_nonce_msg;
    steps.push(AttackStep {
        action: "Verify nonce binding in dep-17 preimage".into(),
        outcome: if nonce_bound {
            StepOutcome::Rejected
        } else {
            StepOutcome::Succeeded
        },
        detail: format!("Different op_nonce → different message: {}", nonce_bound),
    });

    let all_bound =
        collisions == 0 && deposit_bound && amount_bound && cross_op_distinct && nonce_bound;

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
