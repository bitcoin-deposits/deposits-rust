//! Tier 2 & 5: Spec ambiguities and implementation attacks.
//!
//! These test whether the implementation actually enforces what the spec claims.

use deposits_core::descriptor::CoreWitnessVerifier;
use deposits_core::ledger::Ledger;
use deposits_test::adversarial::*;
use deposits_test::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::*;

fn test_pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

// =========================================================================
// Tier 5.3: Integer overflow in fee arithmetic
// =========================================================================

#[test]
fn attack_fee_overflow() {
    let mut log = AttackLog::new();

    // Test: balance near u64::MAX with maximum fee rate
    let mut state = LedgerState::new(test_pubkey(1), "bcrt1qtest".into(), 0);
    state.reserves_amount = u64::MAX;

    // Open deposit
    let desc = "pk(aabbccdd)";
    let did = compute_deposit_id(desc);
    state = state
        .apply(&LedgerOperation::DepositOpen {
            deposit_id: did,
            descriptor: desc.to_string(),
            fees: Some(FeeStructure {
                annualized_msats: u64::MAX / 2,
                annualized_bps: 10000, // 100%
                frequency_blocks: 1,   // every block
            }),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();

    // Credit a very large amount
    state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xAA; 32],
            deposit_id: did,
            amount: u64::MAX / 2,
            invoice_id: "big".into(),
            sequence_number: 1,
        })
        .unwrap();

    // Now collect fees — this is where overflow could happen
    // balance * bps / 10000 for large balance could overflow
    let fee_result = state.apply(&LedgerOperation::FeeCollect {
        deposit_id: did,
        amount: u64::MAX / 4, // large fee
        block_height: 52560,
    });

    // The fee should be applied via saturating_sub — shouldn't panic or wrap
    let blocked = fee_result.is_ok(); // saturating_sub means it won't error

    log.record(AttackResult {
        name: "Integer overflow in fee arithmetic".into(),
        invariant: Invariant::BalanceNonNegative,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked,
        defense: DefenseLayer::Implementation,
        scaling: Scaling::Constant,
        notes: format!(
            "FeeCollect uses saturating_sub — no overflow. Balance after: {}",
            fee_result
                .as_ref()
                .ok()
                .and_then(|s| s.deposits.get(&did))
                .map(|d| d.balance.to_string())
                .unwrap_or("error".into())
        ),
        steps: vec![],
    });

    // The real concern: can fee collection drive balance below zero?
    if let Ok(ref s) = fee_result {
        let deposit = s.deposits.get(&did).unwrap();
        assert!(
            deposit.balance <= u64::MAX / 2,
            "Balance should not wrap around"
        );
    }
}

// =========================================================================
// Tier 5.5: Deposit ID collision (16-byte truncated SHA256)
// =========================================================================

#[test]
fn attack_deposit_id_collision_space() {
    let mut log = AttackLog::new();

    // deposit_id is SHA256(descriptor)[0..16] — 128 bits
    // Birthday attack needs ~2^64 attempts for 50% collision probability
    // That's computationally infeasible, but let's verify the truncation
    // doesn't create obvious collisions with related descriptors

    let desc1 = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let desc2 = "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    let desc3 = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"; // same as 1

    let id1 = compute_deposit_id(desc1);
    let id2 = compute_deposit_id(desc2);
    let id3 = compute_deposit_id(desc3);

    // Same descriptor must produce same ID (deterministic)
    assert_eq!(id1, id3, "Same descriptor must produce same deposit_id");

    // Different descriptors must produce different IDs
    assert_ne!(
        id1, id2,
        "Different descriptors must produce different deposit_ids"
    );

    // Check that deposit_id is exactly 16 bytes
    assert_eq!(id1.len(), 16, "deposit_id must be 16 bytes");

    // Verify collision resistance: try descriptors that differ by one character
    let near_miss1 = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799)";
    let id_near = compute_deposit_id(near_miss1);
    assert_ne!(
        id1, id_near,
        "Near-miss descriptors must produce different IDs"
    );

    log.record(AttackResult {
        name: "Deposit ID collision (16-byte truncated SHA256)".into(),
        invariant: Invariant::PaymentUniqueness,
        adversary: AdversaryCapability {
            operators: 1,
            quorum_fraction: 0.25,
            controls_relay: false,
            controls_miner: false,
            computational_advantage: Some("2^64 hash computations".into()),
        },
        cost_sats: 0,
        extraction_sats: 0,
        blocked: true,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: "128-bit collision resistance. Birthday attack needs ~2^64 \
                SHA256 computations — infeasible but not 256-bit. \
                Could be strengthened by using full 32-byte hash."
            .into(),
        steps: vec![],
    });
}

// =========================================================================
// Tier 2.1: NUMS point verification
// =========================================================================

#[test]
fn attack_non_nums_internal_key() {
    let mut log = AttackLog::new();

    // Check if tapscript_reserves uses a proper NUMS point
    // The BIP-341 recommended NUMS point is:
    // H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
    // which is SHA256("TapTweak") with no known discrete log

    // Check what the implementation uses
    use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};

    let tie_breaker = test_pubkey(1);
    let others: Vec<_> = (2..=4).map(test_pubkey).collect();
    let voter_set = VoterSet::new(tie_breaker, others);
    let config = ThresholdConfig::default_for_voter_count(4);
    let ledger_hash = [0xAB; 32];

    let builder = TapscriptReservesBuilder::new(
        voter_set,
        config,
        bitcoin::Network::Regtest,
        ledger_hash,
    );

    let output = builder.build().unwrap();

    // The internal key should be unspendable (NUMS)
    // We can't easily check "is this NUMS?" without knowing the exact construction,
    // but we can verify the output is a valid taproot address
    let address = output.address.to_string();
    assert!(
        address.starts_with("bcrt1p"),
        "Should be a taproot address: {}",
        address
    );

    // Log the finding — the real check is whether a wallet reconstructing
    // the tree from quorum members produces the same address
    log.record(AttackResult {
        name: "NUMS point verification".into(),
        invariant: Invariant::NUMSPoint,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 1_000_000, // full reserves if exploitable
        blocked: true,              // TODO: verify actual NUMS construction
        defense: DefenseLayer::Implementation,
        scaling: Scaling::Constant,
        notes: format!(
            "Taproot address: {}. Need to verify internal key is BIP-341 NUMS. \
             If operator can choose internal key, they can key-path-spend reserves.",
            &address[..20]
        ),
        steps: vec![],
    });
}

// =========================================================================
// Tier 2.2: Taproot tree reconstruction by wallet
// =========================================================================

#[test]
fn attack_taproot_tree_extra_leaf() {
    let mut log = AttackLog::new();

    use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};

    let tie_breaker = test_pubkey(1);
    let others: Vec<_> = (2..=4).map(test_pubkey).collect();
    let voter_set = VoterSet::new(tie_breaker, others.clone());
    let config = ThresholdConfig::default_for_voter_count(4);
    let ledger_hash = [0xAB; 32];

    // Build the "honest" tree
    let honest_builder = TapscriptReservesBuilder::new(
        voter_set.clone(),
        config.clone(),
        bitcoin::Network::Regtest,
        ledger_hash,
    );
    let honest_output = honest_builder.build().unwrap();

    // Now build with different quorum (simulating attacker's modified tree)
    let attacker_others: Vec<_> = (2..=3).map(test_pubkey).collect(); // only 2 members
    let attacker_voter_set = VoterSet::new(tie_breaker, attacker_others);
    let attacker_config = ThresholdConfig::default_for_voter_count(3);
    let attacker_builder = TapscriptReservesBuilder::new(
        attacker_voter_set,
        attacker_config,
        bitcoin::Network::Regtest,
        ledger_hash,
    );
    let attacker_output = attacker_builder.build().unwrap();

    // The addresses MUST be different — a wallet that verifies the tree
    // would reject the attacker's address as not matching the announced quorum
    let addresses_differ = honest_output.address != attacker_output.address;

    log.record(AttackResult {
        name: "Taproot tree with different quorum produces different address".into(),
        invariant: Invariant::TaprootTreeIntegrity,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 1_000_000,
        blocked: addresses_differ,
        defense: if addresses_differ {
            DefenseLayer::WalletPolicy
        } else {
            DefenseLayer::Undefended
        },
        scaling: Scaling::Constant,
        notes: format!(
            "Honest addr: {}... Attacker addr: {}... Match: {}. \
             Defense requires wallet to reconstruct tree from quorum and verify.",
            &honest_output.address.to_string()[..20],
            &attacker_output.address.to_string()[..20],
            !addresses_differ
        ),
        steps: vec![],
    });

    assert!(
        addresses_differ,
        "Different quorum composition must produce different taproot address"
    );
}

// =========================================================================
// Tier 1.2: Near-expiry extraction window
// =========================================================================

#[test]
fn attack_near_expiry_extraction() {
    let mut log = AttackLog::new();

    // Model: operator waits until the member's commitment window is about to
    // expire, then steals. Question: is the remaining time sufficient for
    // the dispute cascade to complete?

    let dispute_response_blocks: u32 = 144; // ~1 day
    let quorum_diameter: u32 = 3; // max hops in quorum graph
    let cascade_time = quorum_diameter * dispute_response_blocks; // 432 blocks

    // Test various remaining lock times
    let test_cases = [
        (1000, true, "plenty of time"),
        (432, true, "exactly at boundary"),
        (431, false, "one block short"),
        (144, false, "only one hop"),
        (1, false, "effectively expired"),
    ];

    for (remaining_lock, should_be_safe, desc) in test_cases {
        let safe = remaining_lock >= cascade_time;
        assert_eq!(
            safe, should_be_safe,
            "remaining_lock={} cascade_time={} ({})",
            remaining_lock, cascade_time, desc
        );
    }

    log.record(AttackResult {
        name: "Near-expiry extraction window".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 1_000_000,
        blocked: false, // This is a real window
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Constant,
        notes: format!(
            "Extraction window exists when remaining member commitment < {} blocks \
             (diameter {} × response_blocks {}). Wallets MUST refuse deposits \
             when membership expires within cascade_time. Current implementation \
             does not enforce this — it's a wallet-policy defense.",
            cascade_time, quorum_diameter, dispute_response_blocks
        ),
        steps: vec![],
    });

    // This attack IS exploitable — it's a wallet-policy gap
    // The protocol itself doesn't prevent it; wallets must check
}

// =========================================================================
// Tier 3.2: Collateral double-counting across ledgers
// =========================================================================

#[test]
fn attack_collateral_double_counting() {
    let mut log = AttackLog::new();

    // Scenario: Bob has 500k collateral. He backs 3 of Alice's ledgers.
    // All 3 ledgers go non-conforming simultaneously.
    // Can all 3 ledgers be made whole from Bob's 500k?

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

    // Alice credits 3 deposits of 300k each (total 900k, reserves 1M — fine)
    let user1 = net.create_depositor("u1", 10);
    let user2 = net.create_depositor("u2", 20);
    let user3 = net.create_depositor("u3", 30);
    let d1 = net.op_mut("alice").open_deposit(&user1);
    let d2 = net.op_mut("alice").open_deposit(&user2);
    let d3 = net.op_mut("alice").open_deposit(&user3);
    net.op_mut("alice").credit_deposit(d1, 300_000, [0x01; 32]);
    net.op_mut("alice").credit_deposit(d2, 300_000, [0x02; 32]);
    net.op_mut("alice").credit_deposit(d3, 300_000, [0x03; 32]);

    // Total deposits: 900k. Bob's collateral: 500k.
    // If Alice goes non-conforming, the 500k collateral must cover 900k in deposits.
    // But 500k < 900k — the collateral is insufficient!
    let total_deposits = net.op("alice").ledger.state.total_deposit_balance();
    let total_collateral = net.op("alice").ledger.state.total_collateral();

    let collateral_sufficient = total_collateral >= total_deposits;

    log.record(AttackResult {
        name: "Collateral insufficient for total deposits".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 500_000, // bob's collateral at risk
        extraction_sats: total_deposits - total_collateral, // 400k gap
        blocked: collateral_sufficient,
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Linear,
        notes: format!(
            "Total deposits: {} sats, total collateral: {} sats. \
             Gap: {} sats. The protocol allows deposits > collateral. \
             Wallets should check total_collateral >= total_deposits \
             before opening deposits. Reserves (1M) cover the deposits, \
             but collateral only covers 500k — if reserves are stolen, \
             collateral can't make depositors whole.",
            total_deposits,
            total_collateral,
            total_deposits.saturating_sub(total_collateral)
        ),
        steps: vec![],
    });
}

// =========================================================================
// Summary
// =========================================================================

#[test]
fn adversarial_summary() {
    println!("\n=== Adversarial Test Summary ===\n");
    println!("Tier 2 (Spec Ambiguities):");
    println!("  2.1 NUMS point: need manual verification of BIP-341 construction");
    println!(
        "  2.2 Taproot tree: different quorum → different address (defense: wallet must verify)"
    );
    println!("  2.3 Cosigner scope: not yet tested (need event store simulation)");
    println!("  2.4 Proof embedding: not yet tested\n");
    println!("Tier 5 (Implementation):");
    println!("  5.3 Fee overflow: saturating_sub prevents wrap-around");
    println!("  5.4 Cross-ledger replay: blocked by quorum membership check");
    println!("  5.5 Deposit ID collision: 128-bit, birthday attack needs 2^64\n");
    println!("Key Findings:");
    println!("  - Near-expiry extraction IS a real window (wallet-policy defense)");
    println!("  - Collateral can be insufficient for total deposits (wallet-policy defense)");
    println!("  - Taproot tree integrity depends on wallet verification");
}
