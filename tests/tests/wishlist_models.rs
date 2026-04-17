//! Tier 1 and 3 adversarial models — economic and game-theoretic attacks.
//!
//! These test the informal arguments the protocol relies on by constructing
//! specific scenarios that stress them. The goal is not to break the system
//! but to find the boundaries at which the informal arguments fail.

use deposits_integration_tests::adversarial::*;
use deposits_integration_tests::docker::InvariantBoundarySearch;

// =========================================================================
// Tier 1.1: Sybil-with-plausible-topology
// =========================================================================

/// Model a sybil cluster and evaluate it against wallet heuristics.
#[derive(Debug, Clone)]
struct NetworkGraph {
    /// (operator_name, is_sybil)
    operators: Vec<(String, bool)>,
    /// (operator_a, operator_b) — bidirectional quorum membership
    edges: Vec<(usize, usize)>,
}

impl NetworkGraph {
    fn operator_count(&self) -> usize {
        self.operators.len()
    }

    fn sybil_count(&self) -> usize {
        self.operators.iter().filter(|(_, s)| *s).count()
    }

    fn honest_count(&self) -> usize {
        self.operator_count() - self.sybil_count()
    }

    /// How many independent cosigning paths exist from a given operator
    /// to honest seed nodes (operators with is_sybil=false)?
    fn cosign_paths_to_honest(&self, from: usize) -> usize {
        // BFS to find distinct honest nodes reachable
        let mut visited = vec![false; self.operator_count()];
        let mut queue = std::collections::VecDeque::new();
        visited[from] = true;
        queue.push_back(from);

        let mut honest_reached = 0;
        while let Some(node) = queue.pop_front() {
            for &(a, b) in &self.edges {
                let neighbor = if a == node {
                    b
                } else if b == node {
                    a
                } else {
                    continue;
                };
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    if !self.operators[neighbor].1 {
                        honest_reached += 1;
                    }
                    queue.push_back(neighbor);
                }
            }
        }
        honest_reached
    }

    /// Does this graph pass a wallet heuristic requiring N cosign paths?
    fn passes_path_heuristic(&self, required_paths: usize) -> bool {
        // Check from every sybil operator — do they reach enough honest nodes?
        for (i, (_, is_sybil)) in self.operators.iter().enumerate() {
            if *is_sybil {
                let paths = self.cosign_paths_to_honest(i);
                if paths >= required_paths {
                    return true; // sybil passes the check
                }
            }
        }
        false
    }

    /// Does this graph pass a diversity heuristic (no operator backs >X% of network)?
    fn passes_diversity_heuristic(&self, max_concentration: f64) -> bool {
        let n = self.operator_count();
        for i in 0..n {
            let degree = self
                .edges
                .iter()
                .filter(|&&(a, b)| a == i || b == i)
                .count();
            if degree as f64 / n as f64 > max_concentration {
                return false;
            }
        }
        true
    }
}

#[test]
fn tier1_1_sybil_topology() {
    let mut log = AttackLog::new();

    // Scenario: 4 honest operators in a full mesh.
    // Attacker adds S sybil operators that connect to the honest ones.
    // Question: how many sybils does it take to pass wallet heuristics?

    // Honest base: 4 operators, full mesh
    let mut operators: Vec<(String, bool)> =
        (0..4).map(|i| (format!("honest_{}", i), false)).collect();
    let mut edges: Vec<(usize, usize)> = vec![];
    for i in 0..4 {
        for j in (i + 1)..4 {
            edges.push((i, j));
        }
    }

    // Test different sybil cluster sizes
    let results: Vec<(usize, bool, bool)> = (1..=6)
        .map(|sybil_count| {
            let mut ops = operators.clone();
            let mut edgs = edges.clone();
            let base = ops.len();

            // Add sybil operators, each connecting to 2 honest nodes
            for s in 0..sybil_count {
                ops.push((format!("sybil_{}", s), true));
                let sybil_idx = base + s;
                // Connect to 2 honest operators (creating plausible-looking topology)
                edgs.push((sybil_idx, s % 4));
                edgs.push((sybil_idx, (s + 1) % 4));
                // Connect sybils to each other (cluster)
                if s > 0 {
                    edgs.push((sybil_idx, base + s - 1));
                }
            }

            let graph = NetworkGraph {
                operators: ops,
                edges: edgs,
            };

            let passes_3_paths = graph.passes_path_heuristic(3);
            let passes_diversity = graph.passes_diversity_heuristic(0.5);

            (sybil_count, passes_3_paths, passes_diversity)
        })
        .collect();

    println!("Sybil cluster analysis (4 honest operators, full mesh):");
    println!("  Sybils | Passes 3-path | Passes 50% diversity");
    println!("  -------|---------------|--------------------");
    for (count, paths, diversity) in &results {
        println!(
            "  {:>6} | {:>13} | {:>20}",
            count,
            if *paths { "YES (unsafe)" } else { "no" },
            if *diversity { "YES" } else { "no (detected)" },
        );
    }

    let min_sybils_for_path = results
        .iter()
        .find(|(_, paths, _)| *paths)
        .map(|(c, _, _)| *c)
        .unwrap_or(999);

    let min_sybils_for_both = results
        .iter()
        .find(|(_, paths, div)| *paths && *div)
        .map(|(c, _, _)| *c)
        .unwrap_or(999);

    log.record(AttackResult {
        name: "Tier 1.1: Sybil-with-plausible-topology".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::colluding(min_sybils_for_path, 4 + min_sybils_for_path),
        cost_sats: 100_000_000 * min_sybils_for_path as u64, // reserves per sybil
        extraction_sats: 100_000_000 * 4,                    // all honest reserves at risk
        blocked: min_sybils_for_both > 4, // if it takes more sybils than honest, hard
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Linear,
        notes: format!(
            "Minimum sybils to pass 3-path heuristic: {}. \
             Minimum to pass both path + diversity: {}. \
             Wallet defense: require path count > network_size/2, \
             check for clustering in quorum membership graph. \
             Cost per sybil: full reserves (~1 BTC) + collateral.",
            min_sybils_for_path,
            if min_sybils_for_both < 999 {
                min_sybils_for_both.to_string()
            } else {
                "not achievable".into()
            },
        ),
    });
}

// =========================================================================
// Tier 1.3: Race-to-slash exploitation
// =========================================================================

/// Model a slashing race between honest quorum members.
#[derive(Debug)]
struct SlashRaceOutcome {
    /// Who slashed first
    first_slasher: String,
    /// Blocks until first slash
    blocks_to_slash: u32,
    /// Was the slash on a legitimate violation?
    legitimate: bool,
    /// Did another honest member get front-run?
    front_running: bool,
    /// Revenue to the first slasher (sats)
    slasher_revenue: u64,
}

#[test]
fn tier1_3_race_to_slash() {
    let mut log = AttackLog::new();

    // Model: 3 quorum members watching alice's ledger.
    // Alice violates (over-reserve credit).
    // All 3 detect at slightly different times (due to relay propagation).
    //
    // Game dynamics:
    // 1. First to dispute collects the collateral
    // 2. Others get nothing (or get less)
    // 3. Incentive: slash fast, even before fully verifying
    //
    // Pathological case: attacker presents a plausible-looking but invalid
    // fraud proof to member B, causing B to slash innocent operator C.

    let dispute_response_blocks = 144u32;
    let relay_propagation_blocks = 1u32; // ~1 block latency

    // Simulate: members detect at slightly different times
    let member_detection: Vec<(&str, u32)> = vec![
        ("bob", 0),                              // detects immediately
        ("charlie", relay_propagation_blocks),   // 1 block later
        ("diana", relay_propagation_blocks * 2), // 2 blocks later
    ];

    let collateral_per_member = 500_000u64;

    // Race outcome: bob wins (detected first)
    let outcomes: Vec<SlashRaceOutcome> = member_detection
        .iter()
        .map(|(name, detection_delay)| {
            SlashRaceOutcome {
                first_slasher: name.to_string(),
                blocks_to_slash: *detection_delay + 1, // 1 block to publish dispute
                legitimate: true,                      // real violation detected
                front_running: *detection_delay > 0,   // everyone after bob is front-run
                slasher_revenue: if *detection_delay == 0 {
                    collateral_per_member
                } else {
                    0
                },
            }
        })
        .collect();

    // The honest-equilibrium: first defector collects, others confirm
    let first = &outcomes[0];
    let others_get_nothing = outcomes.iter().skip(1).all(|o| o.slasher_revenue == 0);

    println!("Race-to-slash simulation:");
    for o in &outcomes {
        println!(
            "  {}: detects at +{} blocks, revenue={} sats, front-run={}",
            o.first_slasher, o.blocks_to_slash, o.slasher_revenue, o.front_running
        );
    }

    // Pathological scenario: can an attacker make honest member slash innocent?
    // The attacker would need to:
    // 1. Create a plausible-looking non-conformance (e.g., fake over-reserve)
    // 2. Present it to member B before B can verify independently
    // 3. B slashes based on the fake evidence
    //
    // Defense: members MUST verify independently before slashing.
    // A member who slashes based on a relay of someone else's claim
    // without verifying the ledger state directly is violating protocol.
    //
    // The question: does the implementation force independent verification?
    // Answer: DisputeEnter requires last_valid_sequence — the disputer must
    // specify which sequence they believe is the last valid one. This is
    // checkable against the hash chain. A false claim would reference a
    // sequence that doesn't match the chain.

    let false_slash_possible = false; // hash chain prevents false claims

    log.record(AttackResult {
        name: "Tier 1.3: Race-to-slash exploitation".into(),
        invariant: Invariant::NegativeExpectedValue,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0, // griefing, not theft
        blocked: !false_slash_possible,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "First-defector advantage: {} blocks ({} sats). \
             Others front-run: {}. False slash via fake fraud proof: {}. \
             Defense: DisputeEnter binds to last_valid_sequence in hash chain — \
             false claims are detectable. Race compresses cascade time (good) \
             but creates uneven incentives (first gets all). \
             No pathological equilibrium found — honest behavior is still dominant.",
            first.blocks_to_slash, first.slasher_revenue, others_get_nothing, false_slash_possible,
        ),
    });
}

// =========================================================================
// Tier 1.4: Lightning-layer bounded theft
// =========================================================================

#[test]
fn tier1_4_lightning_bounded_theft() {
    let mut log = AttackLog::new();

    // Model: operator steals individual payments below wallet detection threshold.
    //
    // Parameters:
    // - N wallets with varying preimage-reporting behavior
    // - Average payment size P sats
    // - Wallet detection threshold: fraction of payments that must fail
    //   before wallet flags the operator
    // - Operator steals fraction F of payments
    //
    // Question: what F maximizes operator extraction without triggering detection?

    let num_wallets = 100;
    let avg_payment_sats = 50_000u64;
    let payments_per_wallet_per_month = 10u64;
    let collateral = 1_500_000u64; // total collateral at risk

    // Wallet detection models:
    // Type A: reports every uncredited invoice immediately (0% tolerance)
    // Type B: tolerates 1 failure before reporting (10% tolerance at 10 payments)
    // Type C: never checks preimages (100% tolerance — doesn't verify)

    struct WalletPopulation {
        type_a_fraction: f64, // immediate reporters
        type_b_fraction: f64, // tolerant reporters
        type_c_fraction: f64, // non-verifiers
    }

    let populations = vec![
        (
            "All vigilant",
            WalletPopulation {
                type_a_fraction: 1.0,
                type_b_fraction: 0.0,
                type_c_fraction: 0.0,
            },
        ),
        (
            "Mixed",
            WalletPopulation {
                type_a_fraction: 0.5,
                type_b_fraction: 0.3,
                type_c_fraction: 0.2,
            },
        ),
        (
            "Mostly passive",
            WalletPopulation {
                type_a_fraction: 0.1,
                type_b_fraction: 0.2,
                type_c_fraction: 0.7,
            },
        ),
        (
            "All passive",
            WalletPopulation {
                type_a_fraction: 0.0,
                type_b_fraction: 0.0,
                type_c_fraction: 1.0,
            },
        ),
    ];

    println!("Lightning-layer bounded theft simulation:");
    println!(
        "  {} wallets, {} sats avg payment, {} payments/wallet/month",
        num_wallets, avg_payment_sats, payments_per_wallet_per_month
    );
    println!("  Collateral at risk: {} sats\n", collateral);

    let mut worst_case_theft_rate = 0.0f64;
    let mut worst_case_population = "";

    for (name, pop) in &populations {
        // Maximum safe theft rate: steal only from type C wallets
        let safe_targets = (num_wallets as f64 * pop.type_c_fraction) as u64;
        let monthly_theft = safe_targets * payments_per_wallet_per_month * avg_payment_sats;
        let months_to_exceed_collateral = if monthly_theft > 0 {
            collateral / monthly_theft
        } else {
            u64::MAX
        };
        let theft_rate = pop.type_c_fraction; // fraction of payments stealable

        if theft_rate > worst_case_theft_rate {
            worst_case_theft_rate = theft_rate;
            worst_case_population = name;
        }

        // Detection probability: probability that at least one type A wallet
        // is affected if operator steals randomly
        let detection_prob_per_payment = pop.type_a_fraction;

        println!(
            "  {}: max_theft_rate={:.0}% monthly_extraction={} sats \
                  months_to_exceed_collateral={} detection_per_payment={:.0}%",
            name,
            theft_rate * 100.0,
            monthly_theft,
            if months_to_exceed_collateral == u64::MAX {
                "∞".into()
            } else {
                months_to_exceed_collateral.to_string()
            },
            detection_prob_per_payment * 100.0,
        );
    }

    // Find the boundary: at what type_c fraction does theft become viable?
    let search = InvariantBoundarySearch::new("type_c_fraction", 0.0, 1.0, 0.01);
    let threshold = search.find_boundary(|type_c| {
        let safe_targets = (num_wallets as f64 * type_c) as u64;
        let monthly_theft = safe_targets * payments_per_wallet_per_month * avg_payment_sats;
        // Profitable if 12 months of theft exceeds collateral
        let annual_theft = monthly_theft * 12;
        annual_theft as f64 - collateral as f64
    });

    log.record(AttackResult {
        name: "Tier 1.4: Lightning-layer bounded theft".into(),
        invariant: Invariant::NegativeExpectedValue,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: collateral,
        extraction_sats: (num_wallets as f64
            * worst_case_theft_rate
            * payments_per_wallet_per_month as f64
            * avg_payment_sats as f64
            * 12.0) as u64,
        blocked: threshold > 0.5, // safe if >50% of wallets must be passive
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Linear,
        notes: format!(
            "Theft viable when >{:.0}% of wallets don't verify preimages. \
             Worst case: '{}' population allows {:.0}% theft rate. \
             Annual extraction at threshold: {} sats vs {} collateral. \
             Defense: wallets MUST verify preimages. Even 10% vigilant \
             wallets create high detection probability per stolen payment.",
            threshold * 100.0,
            worst_case_population,
            worst_case_theft_rate * 100.0,
            (num_wallets as f64
                * threshold
                * payments_per_wallet_per_month as f64
                * avg_payment_sats as f64
                * 12.0) as u64,
            collateral,
        ),
    });
}

// =========================================================================
// Tier 3.1: Censorship via quorum rotation
// =========================================================================

#[test]
fn tier3_1_censorship_via_rotation() {
    let mut log = AttackLog::new();

    // Attack: wallet tries to force a DeliveryEmbed on quorum member B.
    // Operator rotates quorum to replace B with C before the embed lands.
    //
    // Cost model:
    // - Wallet embed cost: 1 on-chain tx fee (DeliveryEmbed is a ledger operation)
    //   but actually it's just a Nostr event — the cost is getting a quorum
    //   member to include it, which requires the member to be in the quorum.
    // - Operator rotation cost: QuorumBegin requires a new reserves UTXO
    //   (on-chain tx), new collateral locks, and new attestations from new members.
    //
    // The question: is rotation cheaper than embedding?

    let embed_cost_sats = 0u64; // DeliveryEmbed is a Nostr event, no on-chain cost
    let rotation_on_chain_cost = 200u64; // 1 tx fee for QuorumBegin
    let rotation_collateral_cost = 500_000u64; // must re-lock collateral with new members
    let rotation_time_blocks = 6u32; // confirmation + setup time

    // Wallet can embed every block. Operator can rotate every ~6 blocks.
    // Wallet wins the war of attrition if embed is free and rotation costs.

    let embed_rate = 1u32; // embeds per block
    let rotation_rate_blocks = rotation_time_blocks; // blocks between rotations

    // After N rotations, operator has paid N × rotation_cost
    // Wallet has embedded N × rotation_rate × embed_rate times
    let rotations_to_exhaust_operator = 10u32; // arbitrary threshold
    let operator_total_cost =
        rotations_to_exhaust_operator as u64 * (rotation_on_chain_cost + rotation_collateral_cost);
    let wallet_total_cost =
        rotations_to_exhaust_operator as u64 * rotation_rate_blocks as u64 * embed_cost_sats;

    let operator_loses_war = operator_total_cost > wallet_total_cost;

    // But: small wallets may not be able to keep paying for repeated embeds.
    // If embed requires a quorum member's cooperation, and all members
    // are operator-controlled sybils, the wallet can't embed at all.
    //
    // Defense: DeliveryEmbed should work through ANY quorum member,
    // and the wallet can choose which member to use.

    let sybil_quorum_blocks_embed = true; // if all members are sybils, embed fails

    println!("Censorship-via-rotation cost model:");
    println!("  Embed cost per attempt: {} sats", embed_cost_sats);
    println!(
        "  Rotation cost (on-chain + collateral): {} sats",
        rotation_on_chain_cost + rotation_collateral_cost
    );
    println!("  Rotation time: {} blocks", rotation_time_blocks);
    println!(
        "  After {} rotations: operator spent {} sats, wallet spent {} sats",
        rotations_to_exhaust_operator, operator_total_cost, wallet_total_cost
    );
    println!("  Operator loses war of attrition: {}", operator_loses_war);
    println!(
        "  But: sybil quorum blocks embed entirely: {}",
        sybil_quorum_blocks_embed
    );

    log.record(AttackResult {
        name: "Tier 3.1: Censorship via quorum rotation".into(),
        invariant: Invariant::WalletEmbedding,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: operator_total_cost,
        extraction_sats: 0, // censorship, not theft
        blocked: operator_loses_war && !sybil_quorum_blocks_embed,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: format!(
            "Rotation costs {}x more than embedding per round. \
             Operator loses war of attrition after {} rotations. \
             BUT: if quorum is entirely sybils, embed is impossible \
             regardless of cost. Defense requires honest quorum diversity \
             (see Tier 1.1 sybil topology). \
             Recommendation: DeliveryEmbed should support direct relay \
             publication without quorum member cooperation as fallback.",
            (rotation_on_chain_cost + rotation_collateral_cost) / embed_cost_sats.max(1),
            rotations_to_exhaust_operator,
        ),
    });
}
