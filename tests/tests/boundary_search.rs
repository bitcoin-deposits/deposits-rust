//! Invariant boundary search — find thresholds where attacks become profitable.
//!
//! These tests use the InvariantBoundarySearch to binary-search over
//! protocol parameters and find the exact point where an attack flips
//! from deterred (negative EV) to profitable (positive EV).
//!
//! These are pure computation tests — no Docker required. They model
//! the economics with configurable parameters.

use deposits_integration_tests::adversarial::*;
use deposits_integration_tests::docker::InvariantBoundarySearch;

// =========================================================================
// Boundary 1: Collateral ratio threshold
// =========================================================================

#[test]
fn boundary_collateral_ratio() {
    let mut log = AttackLog::new();

    // At what collateral-to-reserves ratio does theft become profitable?
    //
    // Model:
    //   - Operator has R reserves backing deposits
    //   - Operator locks C collateral on N other ledgers
    //   - If operator steals R, they lose C
    //   - Profitable when R > C

    let reserves = 1_000_000u64;
    let quorum_size = 3u64;

    let search = InvariantBoundarySearch::new(
        "collateral_per_member_ratio",
        0.0,  // 0% of reserves as collateral per member
        1.0,  // 100% of reserves as collateral per member
        0.01, // 1% precision
    );

    let threshold = search.find_boundary(|ratio| {
        let collateral_per_member = (reserves as f64 * ratio) as u64;
        let total_collateral = collateral_per_member * quorum_size;

        reserves as f64 - total_collateral as f64 // positive = profitable, negative = deterred
    });

    log.record(AttackResult {
        name: "Collateral ratio threshold".into(),
        invariant: Invariant::SlashingDeterrence,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: reserves,
        blocked: true,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: format!(
            "Theft becomes profitable when per-member collateral < {:.0}% of reserves \
             ({} sats per member × {} members = {} sats total). \
             Current default (50%) → total {:.0}% → deterred.",
            threshold * 100.0,
            (reserves as f64 * threshold) as u64,
            quorum_size,
            (reserves as f64 * threshold) as u64 * quorum_size,
            50.0 * quorum_size as f64
        ),
        steps: vec![],
    });

    // With 3 quorum members, threshold should be ~33% (1/3)
    assert!(
        (threshold - 1.0 / 3.0).abs() < 0.02,
        "Threshold should be ~33% (1/N members): got {:.1}%",
        threshold * 100.0
    );
}

// =========================================================================
// Boundary 2: Near-expiry extraction window
// =========================================================================

#[test]
fn boundary_expiry_window() {
    let mut log = AttackLog::new();

    // At what remaining-lock-blocks does near-expiry extraction become possible?
    //
    // Model:
    //   - Dispute cascade takes diameter × dispute_response_blocks
    //   - If remaining_lock < cascade_time, collateral unlocks before slashing completes
    //   - Attacker steals, then waits for lock to expire

    let dispute_response_blocks = 144u32; // ~1 day
    let quorum_diameter = 3u32;
    let cascade_time = (quorum_diameter * dispute_response_blocks) as f64;

    let search = InvariantBoundarySearch::new(
        "remaining_lock_blocks",
        0.0,    // lock expired
        1000.0, // plenty of time
        1.0,    // 1-block precision
    );

    let threshold = search.find_boundary(|remaining_blocks| {
        // Profitable when lock expires before cascade completes
        if remaining_blocks < cascade_time {
            1.0 // profitable (lock expires, collateral freed)
        } else {
            -1.0 // deterred (cascade completes before lock expires)
        }
    });

    log.record(AttackResult {
        name: "Near-expiry extraction window".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 1_000_000,
        blocked: false, // this IS exploitable
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Constant,
        notes: format!(
            "Extraction profitable when remaining_lock < {:.0} blocks \
             (diameter {} × response {} = {} blocks). \
             Wallets MUST refuse deposits when lock expires within this window.",
            threshold, quorum_diameter, dispute_response_blocks, cascade_time as u32
        ),
        steps: vec![],
    });

    assert!(
        (threshold - cascade_time).abs() < 2.0,
        "Threshold should be ~cascade_time ({}): got {:.0}",
        cascade_time as u32,
        threshold
    );
}

// =========================================================================
// Boundary 3: Detection probability threshold
// =========================================================================

#[test]
fn boundary_detection_probability() {
    let mut log = AttackLog::new();

    // At what detection probability does theft become profitable?
    //
    // Model:
    //   - Operator steals R reserves
    //   - Detection probability p → collateral C is slashed with probability p
    //   - EV = (1-p) × R - p × C
    //   - Profitable when (1-p) × R > p × C → p < R / (R + C)

    let reserves = 1_000_000.0f64;
    let collateral_at_risk = 1_500_000.0f64; // 3 × 500k

    let search = InvariantBoundarySearch::new(
        "detection_probability",
        0.0,   // never detected
        1.0,   // always detected
        0.001, // 0.1% precision
    );

    let threshold = search.find_boundary(|detection_prob| {
        let ev_theft = (1.0 - detection_prob) * reserves;
        let ev_loss = detection_prob * collateral_at_risk;
        ev_theft - ev_loss // positive = profitable
    });

    let analytical = reserves / (reserves + collateral_at_risk);

    log.record(AttackResult {
        name: "Detection probability threshold".into(),
        invariant: Invariant::NegativeExpectedValue,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: collateral_at_risk as u64,
        extraction_sats: reserves as u64,
        blocked: true, // blocked because actual detection >> threshold
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "Theft profitable when detection < {:.1}% (analytical: {:.1}%). \
             With conformance checking, actual detection is ~99%. \
             Margin of safety: {:.1}x above threshold.",
            threshold * 100.0,
            analytical * 100.0,
            0.99 / threshold
        ),
        steps: vec![],
    });

    assert!(
        (threshold - analytical).abs() < 0.01,
        "Threshold should match analytical solution R/(R+C) = {:.3}: got {:.3}",
        analytical,
        threshold
    );
}

// =========================================================================
// Boundary 4: Deposit-to-collateral ratio
// =========================================================================

#[test]
fn boundary_deposit_collateral_gap() {
    let mut log = AttackLog::new();

    // At what deposit level does the collateral gap become exploitable?
    //
    // Model:
    //   - Reserves: R sats (fully backing deposits up to R)
    //   - Collateral: C sats (from quorum members)
    //   - If reserves are stolen, depositors get C from slashing
    //   - Gap = max(0, total_deposits - C) — the unrecoverable amount
    //
    // Question: at what total_deposits / C ratio does the gap appear?

    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    let search = InvariantBoundarySearch::new(
        "deposit_to_collateral_ratio",
        0.0, // no deposits
        5.0, // 5x collateral
        0.01,
    );

    let threshold = search.find_boundary(|ratio| {
        let total_deposits = (collateral as f64 * ratio) as u64;
        if total_deposits > reserves {
            return 1.0; // over-reserved, already blocked by E1
        }
        let gap = total_deposits.saturating_sub(collateral);
        if gap > 0 {
            gap as f64 // gap exists = some depositors can't be made whole
        } else {
            -1.0 // fully covered
        }
    });

    log.record(AttackResult {
        name: "Deposit-to-collateral gap threshold".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: collateral,
        extraction_sats: 0,
        blocked: false,
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Linear,
        notes: format!(
            "Gap appears when total_deposits > {:.0}x collateral (ratio {:.2}). \
             With reserves={}, collateral={}, deposits up to {} are fully covered. \
             Beyond that, depositors face shortfall. \
             Wallet policy: refuse deposits when total > collateral.",
            threshold, threshold, reserves, collateral, collateral
        ),
        steps: vec![],
    });

    // Threshold should be ~1.0 (gap appears when deposits exceed collateral)
    assert!(
        (threshold - 1.0).abs() < 0.02,
        "Gap threshold should be ~1.0x collateral: got {:.2}",
        threshold
    );
}

// =========================================================================
// Boundary 5: Minimum quorum size for safety
// =========================================================================

#[test]
fn boundary_quorum_size() {
    let mut log = AttackLog::new();

    // At what quorum size does a single-operator attack become unprofitable?
    //
    // Model:
    //   - N total operators, attacker controls 1
    //   - Each operator locks C_per_member on each other's ledger
    //   - Attacker's collateral at risk = C_per_member × (N-1)
    //   - Theft = own reserves R
    //   - Deterred when C_per_member × (N-1) >= R

    let reserves = 1_000_000u64;
    let collateral_per_member = 500_000u64;

    let search = InvariantBoundarySearch::new(
        "total_operators",
        2.0,  // minimum network
        10.0, // large network
        0.5,  // half-operator precision
    );

    let threshold = search.find_boundary(|n| {
        let quorum_members = (n as u64).saturating_sub(1); // other operators
        let collateral_at_risk = collateral_per_member * quorum_members;
        reserves as f64 - collateral_at_risk as f64
    });

    log.record(AttackResult {
        name: "Minimum quorum size for deterrence".into(),
        invariant: Invariant::SlashingDeterrence,
        adversary: AdversaryCapability::single_operator(threshold.ceil() as usize),
        cost_sats: collateral_per_member * (threshold.ceil() as u64 - 1),
        extraction_sats: reserves,
        blocked: true,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: format!(
            "With {:.0}k sats collateral per member, need >= {:.0} total operators \
             for single-operator attack to be unprofitable. \
             At N={:.0}: collateral_at_risk = {}k × {} = {}k sats vs {}k theft.",
            collateral_per_member / 1000,
            threshold.ceil(),
            threshold.ceil(),
            collateral_per_member / 1000,
            threshold.ceil() as u64 - 1,
            collateral_per_member / 1000 * (threshold.ceil() as u64 - 1),
            reserves / 1000
        ),
        steps: vec![],
    });

    // With 500k per member, need R/C + 1 = 1M/500k + 1 = 3 operators
    assert!(
        threshold.ceil() as u64 == 3,
        "Minimum operators should be 3 (R/C+1): got {:.0}",
        threshold.ceil()
    );
}

// =========================================================================
// Summary
// =========================================================================

#[test]
fn boundary_search_summary() {
    println!("\n=== Invariant Boundary Summary ===\n");
    println!("  Collateral ratio:     ~33% per member (1/N) for deterrence");
    println!("  Expiry window:        ~432 blocks (diameter × response)");
    println!("  Detection threshold:  ~40% (R/(R+C)) for positive EV");
    println!("  Deposit/collateral:   1.0x — gap appears immediately above collateral");
    println!("  Minimum quorum:       3 operators (with 50% collateral per member)");
    println!("\nThese are the parameters wallets must check before depositing.");
}
