//! Computable topology metrics for wallet ledger selection.
//!
//! Compare multiple graph metrics against the "ground truth" of whether
//! a coalition can profitably attack a given operator. The best metric
//! is the one that most accurately predicts vulnerability.

use std::collections::{HashMap, HashSet, VecDeque};

// Reuse flow graph from topology_mincut
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
                if u == t { break; }
                for v in 0..n {
                    if !visited[v] && residual[u][v] > 0 {
                        visited[v] = true;
                        parent[v] = Some(u);
                        q.push_back(v);
                    }
                }
            }
            if !visited[t] { break; }
            let mut flow = u32::MAX;
            let mut v = t;
            while let Some(u) = parent[v] { flow = flow.min(residual[u][v]); v = u; }
            v = t;
            while let Some(u) = parent[v] { residual[u][v] -= flow; residual[v][u] += flow; v = u; }
            total += flow;
        }
        total
    }
}

fn mincut_to_anchors(n: usize, edges: &[(usize, usize)], target: usize, anchors: &[usize]) -> u32 {
    let ss = n;
    let nn = 2 * (n + 1);
    let mut g = FlowGraph::new(nn);
    for i in 0..n {
        let cap = if i == target { (n + 1) as u32 } else { 1 };
        g.add_edge(2 * i, 2 * i + 1, cap);
    }
    g.add_edge(2 * ss, 2 * ss + 1, (n + 1) as u32);
    for &(u, v) in edges {
        g.add_edge(2 * u + 1, 2 * v, (n + 1) as u32);
        g.add_edge(2 * v + 1, 2 * u, (n + 1) as u32);
    }
    for &a in anchors { g.add_edge(2 * a + 1, 2 * ss, (n + 1) as u32); }
    g.max_flow(2 * target + 1, 2 * ss)
}

// =========================================================================
// Candidate metrics (all O(V+E) or O(V²) — cheap)
// =========================================================================

/// Build adjacency list from edge list.
fn adjacency(n: usize, edges: &[(usize, usize)]) -> Vec<HashSet<usize>> {
    let mut adj = vec![HashSet::new(); n];
    for &(u, v) in edges {
        adj[u].insert(v);
        adj[v].insert(u);
    }
    adj
}

/// Metric 1: Degree — how many quorum connections does this operator have?
/// O(1) per query after adjacency construction.
fn degree(adj: &[HashSet<usize>], target: usize) -> f64 {
    adj[target].len() as f64
}

/// Metric 2: Neighbor diversity — how many DISTINCT second-hop neighbors
/// does this operator reach? Higher = more independent paths to the network.
/// O(degree²) per query.
fn neighbor_diversity(adj: &[HashSet<usize>], target: usize) -> f64 {
    let mut second_hop: HashSet<usize> = HashSet::new();
    for &neighbor in &adj[target] {
        for &nn in &adj[neighbor] {
            if nn != target {
                second_hop.insert(nn);
            }
        }
    }
    second_hop.len() as f64
}

/// Metric 3: Quorum overlap — for each pair of this operator's quorum members,
/// how many OTHER operators share both of them as quorum members?
/// High overlap = correlated failure. Low = independent.
/// O(degree² × N) per query.
fn quorum_overlap(adj: &[HashSet<usize>], target: usize) -> f64 {
    let members: Vec<usize> = adj[target].iter().copied().collect();
    if members.len() < 2 {
        return 0.0;
    }
    let mut total_overlap = 0.0;
    let mut pairs = 0;
    for i in 0..members.len() {
        for j in (i + 1)..members.len() {
            // How many other operators have BOTH members[i] and members[j] in their quorum?
            let shared = adj[members[i]]
                .intersection(&adj[members[j]])
                .filter(|&&x| x != target)
                .count();
            total_overlap += shared as f64;
            pairs += 1;
        }
    }
    if pairs > 0 {
        total_overlap / pairs as f64
    } else {
        0.0
    }
}

/// Metric 4: BFS distance to nearest anchor — how many hops to honest oversight?
/// O(V+E) per query.
fn distance_to_anchor(adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> f64 {
    let anchor_set: HashSet<usize> = anchors.iter().copied().collect();
    let mut visited = vec![false; adj.len()];
    let mut queue = VecDeque::new();
    visited[target] = true;
    queue.push_back((target, 0u32));

    while let Some((node, dist)) = queue.pop_front() {
        if anchor_set.contains(&node) && node != target {
            return dist as f64;
        }
        for &neighbor in &adj[node] {
            if !visited[neighbor] {
                visited[neighbor] = true;
                queue.push_back((neighbor, dist + 1));
            }
        }
    }
    adj.len() as f64 // unreachable
}

/// Metric 5: Anchor coverage — what fraction of this operator's quorum members
/// are themselves directly connected to at least one anchor?
/// O(degree × anchor_degree) per query.
fn anchor_coverage(adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> f64 {
    let anchor_set: HashSet<usize> = anchors.iter().copied().collect();
    let members: Vec<usize> = adj[target].iter().copied().collect();
    if members.is_empty() {
        return 0.0;
    }
    let covered = members
        .iter()
        .filter(|&&m| {
            anchor_set.contains(&m) || adj[m].iter().any(|n| anchor_set.contains(n))
        })
        .count();
    covered as f64 / members.len() as f64
}

/// Metric 6: Neighbor connectivity — what fraction of your neighbor pairs
/// are connected to each other (independent of you)?
/// High = your neighbors form a clique, removing you doesn't disconnect them.
/// Low = you're a bridge, removing you isolates your neighbors.
/// O(degree²) per query.
fn neighbor_connectivity(adj: &[HashSet<usize>], target: usize) -> f64 {
    let members: Vec<usize> = adj[target].iter().copied().collect();
    if members.len() < 2 {
        return 0.0;
    }
    let mut connected_pairs = 0;
    let mut total_pairs = 0;
    for i in 0..members.len() {
        for j in (i + 1)..members.len() {
            total_pairs += 1;
            if adj[members[i]].contains(&members[j]) {
                connected_pairs += 1;
            }
        }
    }
    connected_pairs as f64 / total_pairs as f64
}

/// Metric 7: Local vertex connectivity — min number of your neighbors that
/// must be removed to disconnect you from all anchors, computed via
/// subgraph flow restricted to 2-hop neighborhood.
/// More expensive than other metrics but still O(degree³) not O(V³).
fn local_connectivity(adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> f64 {
    let anchor_set: HashSet<usize> = anchors.iter().copied().collect();
    // Collect 2-hop neighborhood
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

    // Build local flow graph with node-splitting
    let ss = nn; // super-sink
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

    // Connect anchors in neighborhood to super-sink
    let mut has_anchor = false;
    for &a in anchors {
        if let Some(&i) = node_idx.get(&a) {
            g.add_edge(2 * i + 1, 2 * ss, (nn + 1) as u32);
            has_anchor = true;
        }
    }
    if !has_anchor {
        return 0.0;
    }

    let target_i = node_idx[&target];
    g.max_flow(2 * target_i + 1, 2 * ss) as f64
}

/// Metric 8: Composite safety score — weighted combination.
fn composite_score(
    adj: &[HashSet<usize>],
    target: usize,
    anchors: &[usize],
) -> f64 {
    let n = adj.len() as f64;
    let deg = degree(adj, target) / n;
    let div = neighbor_diversity(adj, target) / n;
    let overlap = 1.0 - (quorum_overlap(adj, target) / n).min(1.0);
    let dist = 1.0 / distance_to_anchor(adj, target, anchors).max(1.0);
    let cov = anchor_coverage(adj, target, anchors);
    let nconn = neighbor_connectivity(adj, target);
    let lconn = local_connectivity(adj, target, anchors) / n;

    // Weight: local connectivity and anchor coverage matter most
    0.10 * deg + 0.15 * div + 0.10 * overlap + 0.10 * dist + 0.15 * cov + 0.15 * nconn + 0.25 * lconn
}

// =========================================================================
// Rank correlation
// =========================================================================

fn rank(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    let mut ranks = vec![0.0; n];
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j < n && indexed[j].1 == indexed[i].1 {
            j += 1;
        }
        let avg_rank = (i + j - 1) as f64 / 2.0 + 1.0;
        for k in i..j {
            ranks[indexed[k].0] = avg_rank;
        }
        i = j;
    }
    ranks
}

fn spearman_rank(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len();
    if n < 2 { return f64::NAN; }
    let rx = rank(x);
    let ry = rank(y);
    let mean_rx: f64 = rx.iter().sum::<f64>() / n as f64;
    let mean_ry: f64 = ry.iter().sum::<f64>() / n as f64;
    let mut num = 0.0;
    let mut den_x = 0.0;
    let mut den_y = 0.0;
    for i in 0..n {
        let dx = rx[i] - mean_rx;
        let dy = ry[i] - mean_ry;
        num += dx * dy;
        den_x += dx * dx;
        den_y += dy * dy;
    }
    if den_x == 0.0 || den_y == 0.0 { return f64::NAN; }
    num / (den_x * den_y).sqrt()
}

// =========================================================================
// Topology generators
// =========================================================================

fn ring_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        for j in 1..=q { edges.push((i, (i + j) % n)); }
    }
    edges
}

fn dispersed_topology(n: usize, q: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for i in 0..n {
        let stride = n / (q + 1);
        for j in 1..=q {
            let m = (i + j * stride.max(1)) % n;
            if m != i { edges.push((i, m)); }
        }
    }
    edges
}

fn clustered_topology(n: usize, q: usize, cs: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    let nc = (n + cs - 1) / cs;
    for i in 0..n {
        let c = i / cs;
        let mut added = 0;
        for j in 0..cs {
            let m = c * cs + j;
            if m < n && m != i && added < q { edges.push((i, m)); added += 1; }
        }
        if added < q {
            let bridge = ((c + 1) % nc) * cs;
            if bridge < n && bridge != i { edges.push((i, bridge)); }
        }
    }
    edges
}

// =========================================================================
// Ground truth: coalition attack simulation
// =========================================================================

/// For a given target, what's the minimum coalition that profits?
fn min_profitable_coalition(
    n: usize,
    edges: &[(usize, usize)],
    target: usize,
    reserves: u64,
    collateral: u64,
) -> usize {
    let adj = adjacency(n, edges);
    let quorum: Vec<usize> = adj[target].iter().copied().collect();
    let q = quorum.len();
    let majority = (q + 1) / 2;

    // Try coalition sizes from 1 up
    for k in 1..=q {
        // Best case for attacker: coalition IS the quorum members
        // They need `majority` of the quorum to block dispute
        if k >= majority {
            // Coalition controls the quorum — can steal target's reserves
            // Cost: collateral on honest ledgers
            let honest_neighbors = q - k;
            let cost = collateral * honest_neighbors as u64;
            if reserves > cost {
                return k;
            }
        }
    }
    n // never profitable
}

// =========================================================================
// Correlation test
// =========================================================================

#[test]
fn metric_comparison() {
    println!("\n=== Metric Comparison: Which Predicts Vulnerability? ===");
    println!("  N=16, Q=5, 3 anchors\n");

    let n = 16;
    let q = 5;
    let anchors = vec![0, n / 3, 2 * n / 3];
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    for (topo_name, edges) in &[
        ("ring", ring_topology(n, q)),
        ("dispersed", dispersed_topology(n, q)),
        ("clustered", clustered_topology(n, q, 4)),
    ] {
        let adj = adjacency(n, edges);

        println!("--- {} ---", topo_name);
        println!(
            "{:>3} | {:>4} | {:>5} | {:>5} | {:>5} | {:>5} | {:>5} | {:>5} | {:>7} | {:>6} | {:>8}",
            "Op", "Deg", "Div", "Ovlp", "Dist", "ACov", "NConn", "LConn", "Comp", "Mincut", "MinCoal"
        );
        println!("{}", "-".repeat(95));

        // Collect all data for correlation analysis
        let mut metric_data: Vec<(f64, f64, f64, f64, f64, f64, f64, f64, u32, usize)> = Vec::new();

        for target in 0..n {
            if anchors.contains(&target) { continue; }

            let deg = degree(&adj, target);
            let div = neighbor_diversity(&adj, target);
            let ovlp = quorum_overlap(&adj, target);
            let dist = distance_to_anchor(&adj, target, &anchors);
            let acov = anchor_coverage(&adj, target, &anchors);
            let nconn = neighbor_connectivity(&adj, target);
            let lconn = local_connectivity(&adj, target, &anchors);
            let comp = composite_score(&adj, target, &anchors);
            let mc = mincut_to_anchors(n, edges, target, &anchors);
            let min_coal = min_profitable_coalition(n, edges, target, reserves, collateral);

            println!(
                "{:>3} | {:>4.0} | {:>5.0} | {:>5.1} | {:>5.0} | {:>5.2} | {:>5.2} | {:>5.0} | {:>7.3} | {:>6} | {:>8}",
                target, deg, div, ovlp, dist, acov, nconn, lconn, comp, mc,
                if min_coal >= n { "safe".into() } else { min_coal.to_string() }
            );

            metric_data.push((deg, div, ovlp, dist, acov, nconn, lconn, comp, mc, min_coal));
        }
        println!();

        // Compute rank correlation with mincut
        if metric_data.len() > 1 {
            let mincuts: Vec<f64> = metric_data.iter().map(|d| d.8 as f64).collect();
            let metrics_named: Vec<(&str, Vec<f64>)> = vec![
                ("Degree", metric_data.iter().map(|d| d.0).collect()),
                ("Diversity", metric_data.iter().map(|d| d.1).collect()),
                ("Overlap(-)", metric_data.iter().map(|d| -d.2).collect()), // negate: lower overlap = safer
                ("Distance(-)", metric_data.iter().map(|d| -d.3).collect()), // negate: closer = safer
                ("AnchorCov", metric_data.iter().map(|d| d.4).collect()),
                ("NeighConn", metric_data.iter().map(|d| d.5).collect()),
                ("LocalConn", metric_data.iter().map(|d| d.6).collect()),
                ("Composite", metric_data.iter().map(|d| d.7).collect()),
            ];

            println!("  Correlation with Mincut (Spearman rank):");
            for (name, values) in &metrics_named {
                let r = spearman_rank(&values, &mincuts);
                let bar = if r.is_nan() { "  (no variance)".to_string() }
                    else { format!("  {}{}", if r >= 0.0 { "+" } else { "" }, "█".repeat((r.abs() * 20.0) as usize)) };
                println!("    {:>12}: {:>6.3}{}", name, r, bar);
            }
            println!();
        }
    }

    println!("Legend:");
    println!("  Deg:       Quorum size (direct connections)");
    println!("  Div:       Unique 2nd-hop neighbors (path diversity)");
    println!("  Ovlp:      Avg pairwise quorum member overlap (lower = more independent)");
    println!("  Dist:      BFS hops to nearest anchor");
    println!("  ACov:      Fraction of quorum members within 1 hop of an anchor");
    println!("  NConn:     Neighbor connectivity (fraction of neighbor pairs directly connected)");
    println!("  LConn:     Local vertex connectivity (mincut in 2-hop neighborhood)");
    println!("  Comp:      Weighted composite (higher = safer)");
    println!("  Mincut:    Vertex mincut to anchors (ground truth, expensive)");
    println!("  MinCoal:   Smallest profitable coalition (ground truth, expensive)");
    println!();
    println!("A good cheap metric should correlate with Mincut and MinCoal.");
}

/// Larger network test: N=32 with only 2 anchors => more variance in distance/coverage.
#[test]
fn metric_comparison_large() {
    println!("\n=== Metric Comparison (Large): N=32, Q=5, 2 anchors ===\n");

    let n = 32;
    let q = 5;
    let anchors = vec![0, 16]; // only 2 anchors, far apart
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    for (topo_name, edges) in &[
        ("ring", ring_topology(n, q)),
        ("dispersed", dispersed_topology(n, q)),
        ("clustered", clustered_topology(n, q, 4)),
    ] {
        let adj = adjacency(n, edges);

        println!("--- {} ---", topo_name);

        let mut metric_data: Vec<(f64, f64, f64, f64, f64, f64, f64, f64, u32)> = Vec::new();

        for target in 0..n {
            if anchors.contains(&target) { continue; }

            let deg = degree(&adj, target);
            let div = neighbor_diversity(&adj, target);
            let ovlp = quorum_overlap(&adj, target);
            let dist = distance_to_anchor(&adj, target, &anchors);
            let acov = anchor_coverage(&adj, target, &anchors);
            let nconn = neighbor_connectivity(&adj, target);
            let lconn = local_connectivity(&adj, target, &anchors);
            let comp = composite_score(&adj, target, &anchors);
            let mc = mincut_to_anchors(n, edges, target, &anchors);

            metric_data.push((deg, div, ovlp, dist, acov, nconn, lconn, comp, mc));
        }

        // Just show correlation summary (too many rows for N=32)
        let mincuts: Vec<f64> = metric_data.iter().map(|d| d.8 as f64).collect();
        let metrics_named: Vec<(&str, Vec<f64>)> = vec![
            ("Degree", metric_data.iter().map(|d| d.0).collect()),
            ("Diversity", metric_data.iter().map(|d| d.1).collect()),
            ("Overlap(-)", metric_data.iter().map(|d| -d.2).collect()),
            ("Distance(-)", metric_data.iter().map(|d| -d.3).collect()),
            ("AnchorCov", metric_data.iter().map(|d| d.4).collect()),
            ("NeighConn", metric_data.iter().map(|d| d.5).collect()),
            ("LocalConn", metric_data.iter().map(|d| d.6).collect()),
            ("Composite", metric_data.iter().map(|d| d.7).collect()),
        ];

        // Show mincut distribution
        let mut mincut_counts: HashMap<u32, usize> = HashMap::new();
        for d in &metric_data {
            *mincut_counts.entry(d.8).or_insert(0) += 1;
        }
        let mut mc_sorted: Vec<_> = mincut_counts.into_iter().collect();
        mc_sorted.sort();
        print!("  Mincut distribution: ");
        for (mc, count) in &mc_sorted {
            print!("{}={} ", mc, count);
        }
        println!();

        println!("  Correlation with Mincut (Spearman rank):");
        for (name, values) in &metrics_named {
            let r = spearman_rank(&values, &mincuts);
            let bar = if r.is_nan() { "  (no variance)".to_string() }
                else { format!("  {}{}", if r >= 0.0 { "+" } else { "" }, "█".repeat((r.abs() * 20.0) as usize)) };
            println!("    {:>12}: {:>6.3}{}", name, r, bar);
        }
        println!();
    }
}
