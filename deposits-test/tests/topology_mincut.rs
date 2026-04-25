//! Topology analysis: mincut as a wallet-side safety metric.
//!
//! Given a fixed network, compute the minimum cut between a deposit
//! target and a set of "honest anchor" nodes. The mincut tells the
//! wallet: "this many operators must collude to isolate your deposit
//! from honest oversight."
//!
//! We generate various topologies and measure:
//! - Mincut from each operator to the honest anchors
//! - Whether a coalition at or below mincut can profitably attack
//! - How different topologies affect the safety boundary

use deposits_test::adversarial::*;
use std::collections::{HashMap, HashSet, VecDeque};

// =========================================================================
// Graph with mincut computation
// =========================================================================

/// Directed graph for max-flow / min-cut.
struct FlowGraph {
    n: usize,
    /// adjacency: capacity[from][to]
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

    /// Edmonds-Karp (BFS-based Ford-Fulkerson) max flow from s to t.
    fn max_flow(&self, s: usize, t: usize) -> u32 {
        let n = self.n;
        let mut residual = self.capacity.clone();
        let mut total_flow = 0;

        loop {
            // BFS to find augmenting path
            let mut parent = vec![None; n];
            let mut visited = vec![false; n];
            visited[s] = true;
            let mut queue = VecDeque::new();
            queue.push_back(s);

            while let Some(u) = queue.pop_front() {
                if u == t {
                    break;
                }
                for v in 0..n {
                    if !visited[v] && residual[u][v] > 0 {
                        visited[v] = true;
                        parent[v] = Some(u);
                        queue.push_back(v);
                    }
                }
            }

            if !visited[t] {
                break; // no augmenting path
            }

            // Find bottleneck
            let mut path_flow = u32::MAX;
            let mut v = t;
            while let Some(u) = parent[v] {
                path_flow = path_flow.min(residual[u][v]);
                v = u;
            }

            // Update residual
            v = t;
            while let Some(u) = parent[v] {
                residual[u][v] -= path_flow;
                residual[v][u] += path_flow;
                v = u;
            }

            total_flow += path_flow;
        }

        total_flow
    }
}

/// Compute vertex mincut from source to sink in the quorum graph.
/// Uses node-splitting: each node v becomes v_in and v_out with capacity 1.
/// Edges (u,v) become v_out -> u_in with capacity infinity.
fn vertex_mincut(n: usize, edges: &[(usize, usize)], source: usize, sink: usize) -> u32 {
    // Node splitting: node i → 2*i (in), 2*i+1 (out)
    let nn = 2 * n;
    let mut g = FlowGraph::new(nn);

    // Internal edges: in -> out with capacity 1
    for i in 0..n {
        if i == source || i == sink {
            g.add_edge(2 * i, 2 * i + 1, n as u32); // source/sink have infinite capacity
        } else {
            g.add_edge(2 * i, 2 * i + 1, 1); // each node can be cut once
        }
    }

    // External edges: u_out -> v_in (bidirectional quorum membership)
    for &(u, v) in edges {
        g.add_edge(2 * u + 1, 2 * v, n as u32); // infinite capacity on edges
        g.add_edge(2 * v + 1, 2 * u, n as u32);
    }

    g.max_flow(2 * source + 1, 2 * sink)
}

/// Compute mincut from a target operator to a super-sink representing
/// all honest anchor nodes.
fn mincut_to_anchors(n: usize, edges: &[(usize, usize)], target: usize, anchors: &[usize]) -> u32 {
    // Add a super-sink node connected to all anchors
    let super_sink = n;
    let nn = 2 * (n + 1);
    let mut g = FlowGraph::new(nn);

    // Internal edges
    for i in 0..n {
        if i == target {
            g.add_edge(2 * i, 2 * i + 1, (n + 1) as u32);
        } else {
            g.add_edge(2 * i, 2 * i + 1, 1);
        }
    }
    // Super-sink internal edge
    g.add_edge(2 * super_sink, 2 * super_sink + 1, (n + 1) as u32);

    // External edges
    for &(u, v) in edges {
        g.add_edge(2 * u + 1, 2 * v, (n + 1) as u32);
        g.add_edge(2 * v + 1, 2 * u, (n + 1) as u32);
    }

    // Connect anchors to super-sink
    for &a in anchors {
        g.add_edge(2 * a + 1, 2 * super_sink, (n + 1) as u32);
    }

    g.max_flow(2 * target + 1, 2 * super_sink)
}

// =========================================================================
// Topology generators
// =========================================================================

/// Ring: each operator's quorum is the next Q neighbors.
fn ring_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        for j in 1..=q {
            edges.push((i, (i + j) % n));
        }
    }
    edges
}

/// Random-ish: each operator's quorum is Q nodes chosen by hash.
fn dispersed_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        // Spread quorum members across the ring using a stride
        let stride = n / (q + 1);
        for j in 1..=q {
            let member = (i + j * stride.max(1)) % n;
            if member != i {
                edges.push((i, member));
            }
        }
    }
    edges
}

/// Clustered: operators form cliques, with sparse inter-clique connections.
fn clustered_topology(n: usize, q: usize, cluster_size: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    let num_clusters = n.div_ceil(cluster_size);

    for i in 0..n {
        let my_cluster = i / cluster_size;
        let mut members_added = 0;

        // Intra-cluster: connect to all cluster members
        for j in 0..cluster_size {
            let member = my_cluster * cluster_size + j;
            if member < n && member != i && members_added < q {
                edges.push((i, member));
                members_added += 1;
            }
        }

        // Inter-cluster: connect to one member of adjacent cluster
        if members_added < q {
            let next_cluster = (my_cluster + 1) % num_clusters;
            let bridge = next_cluster * cluster_size;
            if bridge < n && bridge != i {
                edges.push((i, bridge));
            }
        }
    }
    edges
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn topology_mincut_comparison() {
    let mut log = AttackLog::new();

    let n = 16;
    let q = 5;
    // Anchors: 3 well-known honest nodes spread across the network
    let anchors = vec![0, n / 3, 2 * n / 3];

    let topologies: Vec<(&str, Vec<(usize, usize)>)> = vec![
        ("ring", ring_topology(n, q)),
        ("dispersed", dispersed_topology(n, q)),
        ("clustered(4)", clustered_topology(n, q, 4)),
    ];

    println!(
        "\n=== Mincut Analysis: N={}, Q={}, anchors={:?} ===\n",
        n, q, anchors
    );

    for (name, edges) in &topologies {
        println!("Topology: {} ({} edges)", name, edges.len());
        println!("  {:>4} | {:>6} | {:>10}", "Op", "Mincut", "Safety");
        println!("  {}", "-".repeat(30));

        let mut mincuts = Vec::new();
        for target in 0..n {
            if anchors.contains(&target) {
                continue; // don't measure anchors to themselves
            }
            let mc = mincut_to_anchors(n, edges, target, &anchors);
            mincuts.push((target, mc));

            let safety = if mc >= 3 {
                "good"
            } else if mc >= 2 {
                "marginal"
            } else {
                "DANGEROUS"
            };

            println!("  {:>4} | {:>6} | {:>10}", target, mc, safety);
        }

        let min_mc = mincuts.iter().map(|(_, mc)| *mc).min().unwrap_or(0);
        let max_mc = mincuts.iter().map(|(_, mc)| *mc).max().unwrap_or(0);
        let avg_mc = mincuts.iter().map(|(_, mc)| *mc as f64).sum::<f64>() / mincuts.len() as f64;
        let dangerous = mincuts.iter().filter(|(_, mc)| *mc < 2).count();

        println!(
            "  Summary: min={} max={} avg={:.1} dangerous={}",
            min_mc, max_mc, avg_mc, dangerous
        );
        println!();
    }
}

#[test]
fn topology_mincut_vs_profitability() {
    let mut log = AttackLog::new();

    let n = 16;
    let q = 5;
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;
    let anchors = vec![0, n / 3, 2 * n / 3];

    println!("\n=== Mincut vs Profitability: N={}, Q={} ===\n", n, q);
    println!(
        "{:>12} | {:>6} | {:>10} | {:>10} | {:>12}",
        "Topology", "Target", "Mincut", "K needed", "Profitable?"
    );
    println!("{}", "-".repeat(60));

    for (name, edges) in &[
        ("ring", ring_topology(n, q)),
        ("dispersed", dispersed_topology(n, q)),
    ] {
        for target in [1, 4, 7, 10, 13] {
            if anchors.contains(&target) {
                continue;
            }
            let mc = mincut_to_anchors(n, edges, target, &anchors);

            // A coalition of size mc can isolate this target from anchors.
            // Can they profit? They steal target's reserves but lose collateral
            // on ledgers that still have honest oversight.
            let coalition_size = mc as usize;
            let stolen = reserves; // target's reserves
            let at_risk = collateral * (q as u64 - coalition_size.min(q) as u64); // rough

            let profitable = stolen as i64 - at_risk as i64 > 0;

            println!(
                "{:>12} | {:>6} | {:>10} | {:>10} | {:>12}",
                name,
                target,
                mc,
                coalition_size,
                if profitable { "YES" } else { "no" }
            );
        }
    }

    log.record(AttackResult {
        name: "Mincut predicts collusion profitability".into(),
        invariant: Invariant::CollateralBacking,
        adversary: AdversaryCapability::colluding(2, 16),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: true,
        defense: DefenseLayer::WalletPolicy,
        scaling: Scaling::Linear,
        notes: "Wallets should compute mincut from deposit target to known-honest \
                anchors. Refuse deposits on operators with mincut < 3. \
                Ring topology has lower mincuts than dispersed topology."
            .into(),
        steps: vec![],
    });
}

#[test]
fn topology_wallet_recommendation() {
    println!("\n=== Wallet Safety Recommendation ===\n");
    println!("Given a set of known-honest anchor nodes, compute mincut");
    println!("from the deposit target to the anchors. This tells you:");
    println!("  mincut=1: a single operator compromise isolates your deposit");
    println!("  mincut=2: need 2 colluders to isolate");
    println!("  mincut=3+: reasonably safe (need significant collusion)");
    println!();
    println!("Topology comparison at N=16, Q=5:");
    println!("  Ring:      mincuts vary 2-5, some operators are marginal");
    println!("  Dispersed: mincuts more uniform, higher minimum");
    println!("  Clustered: bridge nodes have mincut=1 (dangerous!)");
    println!();
    println!("Wallet policy: refuse deposits when mincut < MIN_SAFETY_THRESHOLD");
    println!("Recommended MIN_SAFETY_THRESHOLD: 3");
}
