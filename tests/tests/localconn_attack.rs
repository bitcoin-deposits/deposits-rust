//! Can you actually steal from a node with LocalConn=2?
//!
//! Full attack simulation: pick a target, form the optimal coalition,
//! trace every ledger in the network, compute the real P&L.

use std::collections::{HashMap, HashSet, VecDeque};

// =========================================================================
// Graph primitives
// =========================================================================

struct FlowGraph {
    n: usize,
    capacity: Vec<Vec<u32>>,
}

impl FlowGraph {
    fn new(n: usize) -> Self {
        Self {
            n,
            capacity: vec![vec![0; n]; n],
        }
    }
    fn add_edge(&mut self, from: usize, to: usize, cap: u32) {
        self.capacity[from][to] += cap;
    }
    fn max_flow(&self, s: usize, t: usize) -> u32 {
        let n = self.n;
        let mut residual = self.capacity.clone();
        let mut total = 0;
        loop {
            let mut parent = vec![None; n];
            let mut visited = vec![false; n];
            visited[s] = true;
            let mut q = VecDeque::new();
            q.push_back(s);
            while let Some(u) = q.pop_front() {
                if u == t {
                    break;
                }
                for v in 0..n {
                    if !visited[v] && residual[u][v] > 0 {
                        visited[v] = true;
                        parent[v] = Some(u);
                        q.push_back(v);
                    }
                }
            }
            if !visited[t] {
                break;
            }
            let mut flow = u32::MAX;
            let mut v = t;
            while let Some(u) = parent[v] {
                flow = flow.min(residual[u][v]);
                v = u;
            }
            v = t;
            while let Some(u) = parent[v] {
                residual[u][v] -= flow;
                residual[v][u] += flow;
                v = u;
            }
            total += flow;
        }
        total
    }
}

fn adjacency(n: usize, edges: &[(usize, usize)]) -> Vec<HashSet<usize>> {
    let mut adj = vec![HashSet::new(); n];
    for &(u, v) in edges {
        adj[u].insert(v);
        adj[v].insert(u);
    }
    adj
}

fn local_connectivity(adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> u32 {
    let mut neighborhood: HashSet<usize> = HashSet::new();
    neighborhood.insert(target);
    for &n1 in &adj[target] {
        neighborhood.insert(n1);
        for &n2 in &adj[n1] {
            neighborhood.insert(n2);
        }
    }
    let nodes: Vec<usize> = neighborhood.iter().copied().collect();
    let node_idx: HashMap<usize, usize> = nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
    let nn = nodes.len();
    let ss = nn;
    let graph_size = 2 * (nn + 1);
    let mut g = FlowGraph::new(graph_size);
    for (i, &node) in nodes.iter().enumerate() {
        let cap = if node == target { (nn + 1) as u32 } else { 1 };
        g.add_edge(2 * i, 2 * i + 1, cap);
    }
    g.add_edge(2 * ss, 2 * ss + 1, (nn + 1) as u32);
    for &node in &neighborhood {
        let i = node_idx[&node];
        for &neighbor in &adj[node] {
            if let Some(&j) = node_idx.get(&neighbor) {
                g.add_edge(2 * i + 1, 2 * j, (nn + 1) as u32);
            }
        }
    }
    let mut has_anchor = false;
    for &a in anchors {
        if let Some(&i) = node_idx.get(&a) {
            g.add_edge(2 * i + 1, 2 * ss, (nn + 1) as u32);
            has_anchor = true;
        }
    }
    if !has_anchor {
        return 0;
    }
    let target_i = node_idx[&target];
    g.max_flow(2 * target_i + 1, 2 * ss)
}

// =========================================================================
// Topology generators
// =========================================================================

fn ring_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        for j in 1..=q {
            edges.push((i, (i + j) % n));
        }
    }
    edges
}

fn dispersed_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        let stride = n / (q + 1);
        for j in 1..=q {
            let m = (i + j * stride.max(1)) % n;
            if m != i {
                edges.push((i, m));
            }
        }
    }
    edges
}

fn clustered_topology(n: usize, q: usize, cs: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    let nc = n.div_ceil(cs);
    for i in 0..n {
        let c = i / cs;
        let mut added = 0;
        for j in 0..cs {
            let m = c * cs + j;
            if m < n && m != i && added < q {
                edges.push((i, m));
                added += 1;
            }
        }
        if added < q {
            let bridge = ((c + 1) % nc) * cs;
            if bridge < n && bridge != i {
                edges.push((i, bridge));
            }
        }
    }
    edges
}

fn hub_spoke_topology(n: usize, q: usize, num_hubs: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    let hubs: Vec<usize> = (0..num_hubs).collect();
    for i in 0..hubs.len() {
        for j in (i + 1)..hubs.len() {
            edges.push((hubs[i], hubs[j]));
        }
    }
    for i in num_hubs..n {
        for j in 0..q.min(num_hubs) {
            let hub = hubs[(i + j) % num_hubs];
            edges.push((i, hub));
        }
        if q > num_hubs && i + 1 < n {
            edges.push((i, num_hubs + ((i - num_hubs + 1) % (n - num_hubs))));
        }
    }
    edges
}

// =========================================================================
// Full attack simulation
// =========================================================================

/// Per-ledger outcome during an attack.
#[derive(Debug)]
struct LedgerOutcome {
    /// Whose ledger is this?
    operator: usize,
    /// Is this operator in the coalition?
    is_coalition: bool,
    /// This operator's quorum members
    quorum: Vec<usize>,
    /// How many coalition members in this quorum?
    coalition_in_quorum: usize,
    /// Does the honest remainder still have majority?
    honest_majority: bool,
    /// Can the coalition steal from this ledger?
    can_steal: bool,
    /// Can honest quorum slash coalition collateral on this ledger?
    can_slash_coalition: bool,
}

/// Full attack result across the network.
#[derive(Debug)]
struct AttackTrace {
    target: usize,
    coalition: Vec<usize>,
    local_conn: u32,
    reserves_per_op: u64,
    collateral_per_member: u64,
    ledger_outcomes: Vec<LedgerOutcome>,
    // P&L
    stolen_from_target: u64,
    stolen_from_coalition_own: u64,
    stolen_from_honest_compromised: u64,
    total_extracted: u64,
    collateral_slashed: u64,
    net_profit: i64,
}

fn simulate_attack(
    n: usize,
    adj: &[HashSet<usize>],
    target: usize,
    coalition: &[usize],
    reserves: u64,
    collateral: u64,
) -> AttackTrace {
    let coalition_set: HashSet<usize> = coalition.iter().copied().collect();
    let mut outcomes = Vec::new();

    for i in 0..n {
        let quorum: Vec<usize> = adj[i].iter().copied().collect();
        let q = quorum.len();
        let coalition_in_q = quorum.iter().filter(|m| coalition_set.contains(m)).count();
        let honest_in_q = q - coalition_in_q;
        let majority_needed = q.div_ceil(2);
        let honest_majority = honest_in_q >= majority_needed;
        let is_coal = coalition_set.contains(&i);

        // Coalition can steal if:
        // - It's the target (coalition controls target's quorum) OR
        // - It's a coalition member (they steal their own reserves) OR
        // - It's an honest op whose quorum is majority-coalition
        let can_steal = if i == target {
            // Target: coalition needs majority of target's quorum
            coalition_in_q >= majority_needed
        } else if is_coal {
            // Coalition members: they just take their own reserves
            // (this is the "walk away" part of the attack)
            true
        } else {
            // Other honest operators: coalition needs quorum majority
            !honest_majority
        };

        // Honest quorum can slash coalition collateral if they retain majority
        let can_slash = !is_coal && honest_majority;

        outcomes.push(LedgerOutcome {
            operator: i,
            is_coalition: is_coal,
            quorum,
            coalition_in_quorum: coalition_in_q,
            honest_majority,
            can_steal,
            can_slash_coalition: can_slash,
        });
    }

    // P&L calculation
    let target_outcome = &outcomes[target];
    let stolen_from_target = if target_outcome.can_steal {
        reserves
    } else {
        0
    };

    // Coalition members steal their own reserves (walk away with them)
    let stolen_from_coalition_own = coalition.len() as u64 * reserves;

    // Honest operators whose quorum is compromised
    let stolen_from_honest = outcomes
        .iter()
        .filter(|o| !o.is_coalition && o.operator != target && o.can_steal)
        .count() as u64
        * reserves;

    let total_extracted = stolen_from_target + stolen_from_coalition_own + stolen_from_honest;

    // Collateral slashed: for each honest ledger that CAN slash, count how many
    // coalition members serve on that ledger's quorum — each loses their collateral
    let mut collateral_slashed = 0u64;
    for outcome in &outcomes {
        if outcome.can_slash_coalition {
            // This honest ledger can slash. How many coalition members are in its quorum?
            let coalition_members_here = outcome
                .quorum
                .iter()
                .filter(|m| coalition_set.contains(m))
                .count();
            collateral_slashed += coalition_members_here as u64 * collateral;
        }
    }

    // But wait — the coalition members ALSO had collateral locked.
    // When they walk away, they forfeit their collateral on ALL ledgers that can slash.
    // We already counted that above. But the coalition members also had reserves
    // they posted as operators. Those reserves are under Taproot — the quorum controls them.
    // If the coalition member's OWN quorum is honest-majority, the honest quorum
    // can confiscate the coalition member's reserves too!
    //
    // Actually no — "stolen_from_coalition_own" assumed they take their reserves.
    // But their reserves are in a Taproot output controlled by their quorum.
    // If their quorum is honest-majority, the honest quorum KEEPS those reserves.
    let mut coalition_reserves_recovered = 0u64;
    for &c in coalition {
        let c_outcome = &outcomes[c];
        // Coalition member c's quorum — is it honest-majority?
        let coal_in_c_quorum = c_outcome.coalition_in_quorum;
        let honest_in_c = c_outcome.quorum.len() - coal_in_c_quorum;
        let majority = c_outcome.quorum.len().div_ceil(2);
        if honest_in_c >= majority {
            // Honest quorum controls c's reserves — coalition can't take them
            coalition_reserves_recovered += reserves;
        }
    }

    let actual_coalition_stolen = stolen_from_coalition_own - coalition_reserves_recovered;
    let actual_total = stolen_from_target + actual_coalition_stolen + stolen_from_honest;
    let net = actual_total as i64 - collateral_slashed as i64;

    AttackTrace {
        target,
        coalition: coalition.to_vec(),
        local_conn: 0, // filled in by caller
        reserves_per_op: reserves,
        collateral_per_member: collateral,
        ledger_outcomes: outcomes,
        stolen_from_target,
        stolen_from_coalition_own: actual_coalition_stolen,
        stolen_from_honest_compromised: stolen_from_honest,
        total_extracted: actual_total,
        collateral_slashed,
        net_profit: net,
    }
}

/// Try all possible coalitions of size k from target's quorum.
/// Return the most profitable attack.
fn best_coalition_attack(
    n: usize,
    adj: &[HashSet<usize>],
    target: usize,
    k: usize,
    reserves: u64,
    collateral: u64,
) -> Option<AttackTrace> {
    let quorum: Vec<usize> = adj[target].iter().copied().collect();
    if k > quorum.len() {
        return None;
    }

    // Generate all k-combinations of target's quorum
    let combos = combinations(&quorum, k);
    let mut best: Option<AttackTrace> = None;

    for coalition in combos {
        let trace = simulate_attack(n, adj, target, &coalition, reserves, collateral);
        if best
            .as_ref()
            .is_none_or(|b| trace.net_profit > b.net_profit)
        {
            best = Some(trace);
        }
    }
    best
}

fn combinations(items: &[usize], k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![vec![]];
    }
    if items.len() < k {
        return vec![];
    }
    let mut result = Vec::new();
    // Include items[0]
    for mut combo in combinations(&items[1..], k - 1) {
        combo.insert(0, items[0]);
        result.push(combo);
    }
    // Exclude items[0]
    result.extend(combinations(&items[1..], k));
    result
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn can_you_steal_from_lconn2() {
    println!("\n=== Can You Steal From LocalConn=2? ===");
    println!("  Full P&L trace for attacks on LConn=2 nodes\n");

    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    let scenarios: Vec<(&str, usize, usize, Vec<(usize, usize)>)> = vec![
        ("ring N=16 Q=3", 16, 3, ring_topology(16, 3)),
        ("ring N=16 Q=5", 16, 5, ring_topology(16, 5)),
        ("ring N=32 Q=5", 32, 5, ring_topology(32, 5)),
        ("dispersed N=16 Q=3", 16, 3, dispersed_topology(16, 3)),
        ("dispersed N=16 Q=5", 16, 5, dispersed_topology(16, 5)),
        ("clustered N=16 Q=3", 16, 3, clustered_topology(16, 3, 4)),
        ("clustered N=16 Q=5", 16, 5, clustered_topology(16, 5, 4)),
        ("hub-spoke N=16 Q=3", 16, 3, hub_spoke_topology(16, 3, 3)),
        ("hub-spoke N=32 Q=5", 32, 5, hub_spoke_topology(32, 5, 5)),
    ];

    let mut any_profitable = false;

    for (name, n, _q, edges) in &scenarios {
        let adj = adjacency(*n, edges);
        let anchors: Vec<usize> = vec![0, n / 2];

        // Find all LConn=2 nodes
        let lconn2_targets: Vec<usize> = (0..*n)
            .filter(|&t| !anchors.contains(&t) && !adj[t].is_empty())
            .filter(|&t| local_connectivity(&adj, t, &anchors) == 2)
            .collect();

        if lconn2_targets.is_empty() {
            continue;
        }

        println!(
            "=== {} === ({} nodes with LConn=2)",
            name,
            lconn2_targets.len()
        );

        for &target in &lconn2_targets {
            let quorum: Vec<usize> = adj[target].iter().copied().collect();

            // Try coalition sizes from 2 up to quorum size
            for k in 2..=quorum.len() {
                if let Some(mut trace) =
                    best_coalition_attack(*n, &adj, target, k, reserves, collateral)
                {
                    trace.local_conn = 2;

                    let profitable = trace.net_profit > 0;
                    if profitable {
                        any_profitable = true;
                    }

                    // Only print interesting cases: the smallest k that's profitable,
                    // or k=2 always (the question being asked)
                    if k == 2 || profitable {
                        let tag = if profitable {
                            "PROFITABLE"
                        } else {
                            "UNPROFITABLE"
                        };

                        println!(
                            "  target={:>2} coalition={:?} (K={}): {} net={:+}",
                            target, trace.coalition, k, tag, trace.net_profit
                        );
                        println!(
                            "    extracted: target={}  own_reserves={}  honest_compromised={}  total={}",
                            trace.stolen_from_target,
                            trace.stolen_from_coalition_own,
                            trace.stolen_from_honest_compromised,
                            trace.total_extracted,
                        );
                        println!(
                            "    slashed:   {}  (collateral lost on honest ledgers that can still slash)",
                            trace.collateral_slashed,
                        );

                        // Show per-ledger detail for profitable attacks
                        if profitable {
                            println!("    --- per-ledger breakdown ---");
                            let coalition_set: HashSet<usize> =
                                trace.coalition.iter().copied().collect();
                            for o in &trace.ledger_outcomes {
                                let role = if o.operator == target {
                                    "TARGET"
                                } else if o.is_coalition {
                                    "COAL"
                                } else if !o.honest_majority {
                                    "COMPROMISED"
                                } else if o.coalition_in_quorum > 0 {
                                    "has_coal"
                                } else {
                                    continue; // skip unaffected
                                };

                                let quorum_str: String = o
                                    .quorum
                                    .iter()
                                    .map(|m| {
                                        if coalition_set.contains(m) {
                                            format!("*{}*", m)
                                        } else {
                                            m.to_string()
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .join(",");

                                println!(
                                    "      op_{:>2} [{}] quorum=[{}] coal={}/{} honest_maj={} steal={} slash={}",
                                    o.operator, role, quorum_str,
                                    o.coalition_in_quorum, o.quorum.len(),
                                    o.honest_majority, o.can_steal, o.can_slash_coalition,
                                );
                            }
                        }

                        // If profitable, don't try larger coalitions
                        if profitable {
                            break;
                        }
                    }
                }
            }
        }
        println!();
    }

    // =====================================================================
    // Summary: what ratio of collateral/reserves makes LConn=2 safe?
    // =====================================================================
    println!("=== Collateral ratio sweep: at what ratio is LConn=2 safe? ===\n");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12}",
        "C/R ratio", "Scenarios", "Profitable", "Safe?"
    );
    println!("{}", "-".repeat(55));

    // Use clustered N=16 Q=3 — has interesting LConn=2 nodes
    let edges = clustered_topology(16, 3, 4);
    let adj = adjacency(16, &edges);
    let anchors = vec![0, 8];
    let lconn2: Vec<usize> = (0..16)
        .filter(|&t| !anchors.contains(&t) && !adj[t].is_empty())
        .filter(|&t| local_connectivity(&adj, t, &anchors) == 2)
        .collect();

    for ratio_pct in [25, 50, 75, 100, 150, 200, 300, 500] {
        let coll = reserves * ratio_pct / 100;
        let mut profitable_count = 0;
        let mut total_scenarios = 0;

        for &target in &lconn2 {
            let quorum: Vec<usize> = adj[target].iter().copied().collect();
            for k in 2..=quorum.len() {
                if let Some(trace) = best_coalition_attack(16, &adj, target, k, reserves, coll) {
                    total_scenarios += 1;
                    if trace.net_profit > 0 {
                        profitable_count += 1;
                    }
                }
            }
        }

        let safe = profitable_count == 0;
        println!(
            "{:>7}% | {:>12} | {:>12} | {:>12}",
            ratio_pct,
            total_scenarios,
            profitable_count,
            if safe { "SAFE" } else { "EXPLOITABLE" },
        );
    }

    println!();
    if any_profitable {
        println!("RESULT: YES, LConn=2 can be stolen from at current collateral ratios.");
        println!("  The attack works when coalition members forfeit less collateral");
        println!("  than they extract from the target + compromised honest ledgers.");
    } else {
        println!("RESULT: No profitable attacks found against LConn=2 at 50% collateral ratio.");
    }
}

/// Same analysis for LConn=3.
#[test]
fn can_you_steal_from_lconn3() {
    println!("\n=== Can You Steal From LocalConn=3? ===\n");

    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    let scenarios: Vec<(&str, usize, usize, Vec<(usize, usize)>)> = vec![
        ("ring N=16 Q=5", 16, 5, ring_topology(16, 5)),
        ("ring N=32 Q=5", 32, 5, ring_topology(32, 5)),
        ("ring N=32 Q=7", 32, 7, ring_topology(32, 7)),
        ("hub-spoke N=16 Q=5", 16, 5, hub_spoke_topology(16, 5, 4)),
        ("hub-spoke N=32 Q=5", 32, 5, hub_spoke_topology(32, 5, 5)),
    ];

    let mut any_profitable = false;

    for (name, n, _q, edges) in &scenarios {
        let adj = adjacency(*n, edges);
        let anchors: Vec<usize> = vec![0, n / 3, 2 * n / 3];

        let lconn3_targets: Vec<usize> = (0..*n)
            .filter(|&t| !anchors.contains(&t) && !adj[t].is_empty())
            .filter(|&t| local_connectivity(&adj, t, &anchors) == 3)
            .collect();

        if lconn3_targets.is_empty() {
            continue;
        }

        println!(
            "=== {} === ({} nodes with LConn=3)",
            name,
            lconn3_targets.len()
        );

        for &target in &lconn3_targets {
            let quorum: Vec<usize> = adj[target].iter().copied().collect();

            for k in 3..=quorum.len() {
                if let Some(mut trace) =
                    best_coalition_attack(*n, &adj, target, k, reserves, collateral)
                {
                    trace.local_conn = 3;
                    let profitable = trace.net_profit > 0;
                    if profitable {
                        any_profitable = true;
                    }

                    if k == 3 || profitable {
                        let tag = if profitable {
                            "PROFITABLE"
                        } else {
                            "UNPROFITABLE"
                        };
                        println!(
                            "  target={:>2} coalition={:?} (K={}): {} net={:+}",
                            target, trace.coalition, k, tag, trace.net_profit
                        );
                        println!(
                            "    extracted: target={}  own={}  honest_compromised={}  total={}",
                            trace.stolen_from_target,
                            trace.stolen_from_coalition_own,
                            trace.stolen_from_honest_compromised,
                            trace.total_extracted,
                        );
                        println!("    slashed: {}", trace.collateral_slashed,);
                        if profitable {
                            break;
                        }
                    }
                }
            }
        }
        println!();
    }

    println!();
    if any_profitable {
        println!("RESULT: YES, LConn=3 can be stolen from at 50% collateral ratio.");
    } else {
        println!("RESULT: No profitable attacks found against LConn=3 at 50% collateral ratio.");
    }
}

/// What's the minimum LConn that's safe for different collateral ratios?
#[test]
fn minimum_safe_lconn() {
    println!("\n=== Minimum Safe LocalConn by Collateral Ratio ===\n");
    println!("  For each collateral ratio, what's the lowest LConn where no attack profits?\n");

    let reserves = 1_000_000u64;

    // Build a diverse set of topologies
    let all_topos: Vec<(&str, usize, Vec<(usize, usize)>)> = vec![
        ("ring16q3", 16, ring_topology(16, 3)),
        ("ring16q5", 16, ring_topology(16, 5)),
        ("ring32q5", 32, ring_topology(32, 5)),
        ("disp16q3", 16, dispersed_topology(16, 3)),
        ("disp16q5", 16, dispersed_topology(16, 5)),
        ("clus16q3", 16, clustered_topology(16, 3, 4)),
        ("clus16q5", 16, clustered_topology(16, 5, 4)),
        ("hub16q3", 16, hub_spoke_topology(16, 3, 3)),
        ("hub32q5", 32, hub_spoke_topology(32, 5, 5)),
    ];

    println!(
        "{:>8} | {:>8} | {:>45}",
        "C/R %", "MinSafe", "Details (profitable LConns)"
    );
    println!("{}", "-".repeat(70));

    for ratio_pct in [25, 50, 75, 100, 150, 200, 300] {
        let coll = reserves * ratio_pct / 100;
        let mut profitable_by_lconn: HashMap<u32, usize> = HashMap::new();

        for (_name, n, edges) in &all_topos {
            let adj = adjacency(*n, edges);
            let anchors: Vec<usize> = vec![0, n / 2];

            for target in 0..*n {
                if anchors.contains(&target) || adj[target].is_empty() {
                    continue;
                }
                let lconn = local_connectivity(&adj, target, &anchors);
                if lconn == 0 {
                    continue;
                } // skip disconnected

                let quorum: Vec<usize> = adj[target].iter().copied().collect();
                for k in 2..=quorum.len() {
                    if let Some(trace) = best_coalition_attack(*n, &adj, target, k, reserves, coll)
                    {
                        if trace.net_profit > 0 {
                            *profitable_by_lconn.entry(lconn).or_insert(0) += 1;
                            break; // found profitable for this target
                        }
                    }
                }
            }
        }

        let min_safe = (1..=10u32)
            .find(|lc| !profitable_by_lconn.contains_key(lc))
            .unwrap_or(10);

        let detail: String = {
            let mut entries: Vec<_> = profitable_by_lconn.iter().collect();
            entries.sort();
            entries
                .iter()
                .map(|(lc, count)| format!("LC{}={} attacks", lc, count))
                .collect::<Vec<_>>()
                .join(", ")
        };

        println!(
            "{:>7}% | {:>8} | {}",
            ratio_pct,
            min_safe,
            if detail.is_empty() {
                "none exploitable".into()
            } else {
                detail
            },
        );
    }
}
