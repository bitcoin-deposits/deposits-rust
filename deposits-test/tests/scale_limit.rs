//! Realistic network scaling: N operators, each with ledgers, small quorums.
//!
//! This models the actual deployment topology: many independent operators
//! with 3-7 member quorums, not one giant quorum.

use deposits_test::adversarial::*;
use deposits_test::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::*;
use std::time::Instant;

fn operator_names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("op_{}", i)).collect()
}

// =========================================================================
// How big can we go?
// =========================================================================

#[test]
fn scale_limit_realistic_network() {
    println!("\n=== Realistic Network Scaling ===");
    println!("  N operators, quorum of Q members each\n");
    println!(
        "{:>6} | {:>7} | {:>8} | {:>8} | {:>8}",
        "Ops", "Quorum", "Create", "Setup", "Total"
    );
    println!("{}", "-".repeat(55));

    // Q counts cosigners only — operator is not included. Restricted
    // to {3, 5, 7} per VALID_QUORUM_SIZES (odd-only, capped at the
    // MAX_QUORUM_SIZE_POLICY pre-release ceiling).
    for (n, quorum_size) in [(4, 3), (8, 3), (16, 5), (32, 5), (64, 7), (100, 7)] {
        let names = operator_names(n);
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();

        let t0 = Instant::now();
        let mut net = TestNetwork::new(&refs, 1_000_000);
        let create_ms = t0.elapsed().as_millis();

        // Snapshot all operators
        let snapshots: Vec<_> = net
            .operators
            .iter()
            .map(|o| Operator {
                name: o.name.clone(),
                secret_key: o.secret_key,
                public_key: o.public_key,
                ledger: o.ledger.clone(),
            })
            .collect();

        // Each operator gets a quorum of `quorum_size` neighbors
        let t1 = Instant::now();
        for i in 0..n {
            let q = quorum_size.min(n - 1);
            for j in 1..=q {
                let member_idx = (i + j) % n;
                let member = &snapshots[member_idx];
                let lid = hex::encode(member.ledger.state.ledger_id);
                net.op_mut(&names[i]).add_quorum_member(member, &lid);
            }
            net.op_mut(&names[i]).begin_quorum(1_000_000);
        }
        let setup_ms = t1.elapsed().as_millis();
        let total_ms = t0.elapsed().as_millis();

        // Verify every operator has active quorum
        let all_active = names
            .iter()
            .all(|name| net.op(name).ledger.state.quorum_state == QuorumState::Active);

        println!(
            "{:>6} | {:>5}/{} | {:>6}ms | {:>6}ms | {:>6}ms  all_active={}",
            n,
            net.op(&names[0]).ledger.state.quorum_members.len(),
            quorum_size,
            create_ms,
            setup_ms,
            total_ms,
            all_active,
        );

        assert!(
            all_active,
            "All operators must have active quorum at N={}",
            n
        );
    }
}

// =========================================================================
// Adversarial economics at realistic scale
// =========================================================================

#[test]
fn scale_economics_realistic() {
    let mut log = AttackLog::new();

    println!("\n=== Attack Economics at Scale (quorum=5) ===\n");
    println!(
        "{:>6} | {:>10} | {:>10} | {:>8} | {:>10} | {:>12}",
        "Ops", "Net capital", "Atk cost", "Ratio", "Sybil %", "Detect miss"
    );
    println!("{}", "-".repeat(75));

    for n in [4, 8, 16, 32, 64, 100] {
        let reserves_per_op = 1_000_000u64;
        let collateral_per_member = 500_000u64;
        let quorum_size = 5.min(n - 1) as u64;

        let network_capital = reserves_per_op * n as u64;

        // Attacker controls 1 operator
        // Collateral at risk: locked on `quorum_size` other ledgers
        let attacker_collateral_at_risk = collateral_per_member * quorum_size;
        let ratio = attacker_collateral_at_risk as f64 / reserves_per_op as f64;

        // Sybil: 1 operator out of N
        let sybil_pct = 100.0 / n as f64;

        // Detection: quorum_size independent watchers
        let p_miss = 0.01f64.powi(quorum_size as i32);

        println!(
            "{:>6} | {:>8}M | {:>8}M | {:>6.1}x | {:>8.1}% | {:>12.2e}",
            n,
            network_capital / 1_000_000,
            attacker_collateral_at_risk / 1_000_000,
            ratio,
            sybil_pct,
            p_miss,
        );
    }

    log.record(AttackResult {
        name: "Attack economics at realistic scale (quorum=5)".into(),
        invariant: Invariant::NegativeExpectedValue,
        adversary: AdversaryCapability::single_operator(100),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: true,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: "With fixed quorum size (5), attacker's collateral-to-reserves \
                ratio is constant (2.5x) regardless of network size. \
                Detection probability is constant (1 - 0.01^5 ≈ 1). \
                Sybil cost as % of network decreases with N. \
                The quorum size — not the network size — determines security."
            .into(),
        steps: vec![],
    });
}

// =========================================================================
// Graph connectivity at scale
// =========================================================================

#[test]
fn scale_graph_diameter() {
    println!("\n=== Network Diameter vs Topology ===\n");
    println!(
        "{:>6} | {:>8} | {:>10} | {:>10} | {:>12}",
        "Ops", "Quorum", "Ring diam", "Random d", "Cascade"
    );
    println!("{}", "-".repeat(60));

    let dispute_response = 144u32;

    for n in [4, 8, 16, 32, 64, 100] {
        let quorum_size = 5.min(n - 1);

        // Ring topology: diameter = N / (2 * quorum_size)
        let ring_diameter = (n as f64 / (2.0 * quorum_size as f64)).ceil() as u32;

        // Random graph: diameter ≈ log(N) / log(quorum_size)
        let random_diameter = ((n as f64).ln() / (quorum_size as f64).ln()).ceil() as u32;

        let cascade = random_diameter * dispute_response;

        println!(
            "{:>6} | {:>8} | {:>10} | {:>10} | {:>10} blocks",
            n, quorum_size, ring_diameter, random_diameter, cascade
        );
    }
}
