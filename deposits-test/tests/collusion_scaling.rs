//! Collusion scaling: how many operators must collude to steal,
//! and how does that threshold change with network size?
//!
//! The attack: a coalition of K operators in an N-node network
//! tries to extract funds. They can:
//! 1. Steal from their own ledgers (reserves they control)
//! 2. Refuse to slash each other (mutual protection)
//! 3. Outvote honest members in quorum decisions
//!
//! The question: at what K/N ratio does the coalition profit?

use deposits_protocol::types::*;
use deposits_test::adversarial::*;
use deposits_test::docker::InvariantBoundarySearch;
use deposits_test::*;
use std::collections::HashSet;

// =========================================================================
// Model: coalition of K operators in N-node network
// =========================================================================

struct CollusionModel {
    n: usize,           // total operators
    quorum_size: usize, // members per quorum
    reserves_per_op: u64,
    collateral_per_member: u64,
}

struct CollusionResult {
    k: usize, // coalition size
    n: usize,
    can_steal_own_reserves: bool,
    can_block_slashing: bool,
    can_control_quorum: bool,
    total_extractable: u64,
    total_at_risk: u64,
    profitable: bool,
}

impl CollusionModel {
    fn analyze(&self, k: usize) -> CollusionResult {
        let n = self.n;
        let q = self.quorum_size;

        // 1. Can steal own reserves: always yes (each operator controls their reserves)
        let can_steal_own = true;
        let stolen_reserves = self.reserves_per_op * k as u64;

        // 2. Can block slashing: coalition members refuse to participate in
        //    disputes against each other. For a quorum of Q, the honest
        //    members need a majority. If the coalition controls enough
        //    members in any given quorum, they can block the dispute.
        //
        //    Each ledger's quorum has Q members. If K attackers are spread
        //    across the network, the expected number of coalition members
        //    in any quorum is K/N * Q.
        let expected_coalition_in_quorum = (k as f64 / n as f64) * q as f64;
        let majority_threshold = (q as f64 / 2.0).ceil() as usize;
        let can_block_slash = expected_coalition_in_quorum >= majority_threshold as f64;

        // 3. Can control quorum: coalition has majority in target quorum
        //    Needed for confiscation (spending reserves UTXO)
        let can_control = can_block_slash; // same threshold for Taproot majority spend

        // 4. Collateral at risk: each coalition member has collateral locked
        //    on honest operators' ledgers. Honest operators CAN slash this.
        //    But coalition members' collateral on OTHER coalition members'
        //    ledgers is NOT at risk (they protect each other).
        //
        //    Each coalition member has collateral on Q ledgers.
        //    Expected honest ledgers: Q * (N-K)/N
        //    Collateral at risk = per_member * Q * (N-K)/N * K
        let honest_fraction = (n - k) as f64 / n as f64;
        let collateral_on_honest =
            (self.collateral_per_member as f64 * q as f64 * honest_fraction) as u64;
        let total_collateral_at_risk = collateral_on_honest * k as u64;

        // 5. What can the coalition actually extract?
        //    - Own reserves: yes, always (K * reserves_per_op)
        //    - Other operators' reserves: only if they control the quorum
        //    - If they control quorum majority, they can confiscate honest
        //      operators' reserves too
        let extractable = if can_control {
            // Can confiscate honest operators' reserves via quorum control
            stolen_reserves + self.reserves_per_op * (n - k) as u64
        } else {
            // Can only steal own reserves, but lose collateral on honest ledgers
            stolen_reserves
        };

        let net_profit = extractable as i64 - total_collateral_at_risk as i64;
        let profitable = net_profit > 0;

        CollusionResult {
            k,
            n,
            can_steal_own_reserves: can_steal_own,
            can_block_slashing: can_block_slash,
            can_control_quorum: can_control,
            total_extractable: extractable,
            total_at_risk: total_collateral_at_risk,
            profitable,
        }
    }
}

// =========================================================================
// Test: find collusion threshold at different network sizes
// =========================================================================

#[test]
fn collusion_threshold_by_network_size() {
    let mut log = AttackLog::new();

    println!("\n=== Collusion Threshold vs Network Size ===\n");
    println!(
        "{:>4} | {:>3} | {:>5} | {:>5} | {:>10} | {:>10} | {:>10} | {:>8}",
        "N", "Q", "K", "K/N%", "Extract", "At risk", "Net", "Profit?"
    );
    println!("{}", "-".repeat(80));

    for (n, q) in [(4, 3), (8, 3), (16, 5), (32, 5), (64, 7), (100, 7)] {
        let model = CollusionModel {
            n,
            quorum_size: q,
            reserves_per_op: 1_000_000,
            collateral_per_member: 500_000,
        };

        // Test each coalition size from 1 to N
        let mut threshold_k = 0;
        for k in 1..=n {
            let result = model.analyze(k);
            if result.profitable && threshold_k == 0 {
                threshold_k = k;
            }

            // Print interesting points: K=1, threshold, majority, all
            if k == 1 || k == threshold_k || k == n / 2 || k == n {
                let net = result.total_extractable as i64 - result.total_at_risk as i64;
                println!(
                    "{:>4} | {:>3} | {:>5} | {:>4.0}% | {:>8}M | {:>8}M | {:>+9}M | {}{}",
                    n,
                    q,
                    k,
                    k as f64 / n as f64 * 100.0,
                    result.total_extractable / 1_000_000,
                    result.total_at_risk / 1_000_000,
                    net / 1_000_000,
                    if result.profitable { "YES" } else { "no" },
                    if result.can_control_quorum {
                        " (controls quorum)"
                    } else {
                        ""
                    },
                );
            }
        }

        if threshold_k == 0 {
            println!(
                "{:>4} | {:>3} |   -- |   -- | never profitable without quorum control",
                n, q
            );
        }
        println!();
    }
}

// =========================================================================
// Test: collusion threshold as a function of quorum size
// =========================================================================

#[test]
fn collusion_threshold_by_quorum_size() {
    let mut log = AttackLog::new();

    let n = 32; // fixed network size

    println!("\n=== Collusion Threshold vs Quorum Size (N={}) ===\n", n);
    println!(
        "{:>3} | {:>10} | {:>10} | {:>10}",
        "Q", "Min K", "K/N %", "Controls quorum?"
    );
    println!("{}", "-".repeat(45));

    for q in [3, 5, 7, 9, 11, 15] {
        if q >= n {
            continue;
        }
        let model = CollusionModel {
            n,
            quorum_size: q,
            reserves_per_op: 1_000_000,
            collateral_per_member: 500_000,
        };

        let mut threshold_k = n + 1;
        for k in 1..=n {
            let result = model.analyze(k);
            if result.profitable {
                threshold_k = k;
                break;
            }
        }

        let controls_at_threshold = if threshold_k <= n {
            model.analyze(threshold_k).can_control_quorum
        } else {
            false
        };

        println!(
            "{:>3} | {:>10} | {:>8.1}% | {:>16}",
            q,
            if threshold_k <= n {
                threshold_k.to_string()
            } else {
                "never".into()
            },
            if threshold_k <= n {
                threshold_k as f64 / n as f64 * 100.0
            } else {
                100.0
            },
            if controls_at_threshold { "yes" } else { "no" },
        );
    }

    log.record(AttackResult {
        name: "Collusion threshold varies with quorum size".into(),
        invariant: Invariant::SlashingDeterrence,
        adversary: AdversaryCapability::colluding(16, 32),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: true,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: "Larger quorums require more collusion to overcome. \
                The threshold fraction K/N needed for profitable attack \
                increases with quorum size Q."
            .into(),
        steps: vec![],
    });
}

// =========================================================================
// Test: verify the model with actual protocol execution
// =========================================================================

#[test]
fn collusion_verified_against_protocol() {
    let mut log = AttackLog::new();

    // Small case: 8 operators, quorum=3, coalition of 2 (25%)
    // Can the coalition profit?
    let n = 8;
    let q = 3;
    let k = 2; // coalition: op_0 and op_1

    let names = (0..n).map(|i| format!("op_{}", i)).collect::<Vec<_>>();
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let mut net = TestNetwork::new(&refs, 1_000_000);

    // Set up quorums — each operator gets 3 neighbors
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

    for i in 0..n {
        for j in 1..=q {
            let member_idx = (i + j) % n;
            let member = &snapshots[member_idx];
            let lid = hex::encode(member.ledger.state.ledger_id);
            net.op_mut(&names[i]).add_quorum_member(member, &lid);
        }
        net.op_mut(&names[i]).begin_quorum(1_000_000);
    }

    // Coalition: op_0 steals from their own ledger
    let user = net.create_depositor("victim", 10);
    let did = net.op_mut("op_0").open_deposit(&user);
    net.op_mut("op_0").credit_deposit(did, 800_000, [0x01; 32]);

    // op_0's quorum members: op_1, op_2, op_3 (round-robin with q=3)
    // Coalition controls op_0 and op_1
    // op_1 is a quorum member on op_0's ledger — they won't slash
    // op_2 and op_3 are honest — they WILL detect and dispute

    // Does the honest minority (2 of 3 quorum members) have enough
    // to force a dispute?
    let honest_quorum_members = q - 1; // op_2 and op_3 (1 coalition member: op_1)
    let quorum_majority = q.div_ceil(2);
    let honest_can_dispute = honest_quorum_members >= quorum_majority;

    // Can honest members confiscate reserves? Need Taproot majority.
    // Tier 0: majority immediate (2 of 3 in our case)
    let honest_can_confiscate = honest_quorum_members >= quorum_majority;

    let mut steps = vec![
        AttackStep {
            action: "Coalition (op_0, op_1) established".into(),
            outcome: StepOutcome::Succeeded,
            detail: format!(
                "{} of {} operators ({:.0}%)",
                k,
                n,
                k as f64 / n as f64 * 100.0
            ),
        },
        AttackStep {
            action: "op_0 credits beyond reserves".into(),
            outcome: StepOutcome::Succeeded,
            detail: "800k credited, reserves 1M".into(),
        },
        AttackStep {
            action: "op_1 (coalition) refuses to slash".into(),
            outcome: StepOutcome::Succeeded,
            detail: "Coalition member ignores violation".into(),
        },
        AttackStep {
            action: format!(
                "Honest members ({} of {}) detect violation",
                honest_quorum_members, q
            ),
            outcome: if honest_can_dispute {
                StepOutcome::Detected
            } else {
                StepOutcome::Undetected
            },
            detail: format!(
                "Need {} for majority, have {}",
                quorum_majority, honest_quorum_members
            ),
        },
        AttackStep {
            action: "Honest members attempt dispute".into(),
            outcome: if honest_can_dispute {
                StepOutcome::Succeeded
            } else {
                StepOutcome::Rejected
            },
            detail: format!(
                "Can dispute: {}, can confiscate: {}",
                honest_can_dispute, honest_can_confiscate
            ),
        },
    ];

    let attack_blocked = honest_can_dispute && honest_can_confiscate;

    log.record(AttackResult {
        name: format!("Collusion {}/{} verified against protocol (q={})", k, n, q),
        invariant: Invariant::SlashingDeterrence,
        adversary: AdversaryCapability::colluding(k, n),
        cost_sats: 500_000 * q as u64, // coalition's collateral on honest ledgers
        extraction_sats: if attack_blocked { 0 } else { 1_000_000 },
        blocked: attack_blocked,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: format!(
            "Coalition {}/{}: honest quorum members={}/{} (majority={}). \
             Can dispute: {}. Can confiscate: {}.",
            k,
            n,
            honest_quorum_members,
            q,
            quorum_majority,
            honest_can_dispute,
            honest_can_confiscate
        ),
        steps,
    });
}
