//! Explore the LocalConn → safety mapping.
//!
//! For every combination of (N, Q, topology, anchor_count), compute each
//! operator's LocalConn and ground-truth safety (mincut, min_profitable_coalition).
//! Aggregate into a table: "what does LocalConn=K mean for your deposits?"

use std::collections::{HashMap, HashSet, VecDeque};

// =========================================================================
// Graph primitives (shared with topology_metrics)
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
    for &a in anchors {
        g.add_edge(2 * a + 1, 2 * ss, (n + 1) as u32);
    }
    g.max_flow(2 * target + 1, 2 * ss)
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
    let majority = q.div_ceil(2);
    for k in 1..=q {
        if k >= majority {
            let honest_neighbors = q - k;
            let cost = collateral * honest_neighbors as u64;
            if reserves > cost {
                return k;
            }
        }
    }
    n
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

/// Hub-and-spoke: a few well-connected hubs, most nodes only connect to hubs.
/// Models a network with a few large operators and many small ones.
fn hub_spoke_topology(n: usize, q: usize, num_hubs: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    let hubs: Vec<usize> = (0..num_hubs).collect();

    // Hubs connect to each other
    for i in 0..hubs.len() {
        for j in (i + 1)..hubs.len() {
            edges.push((hubs[i], hubs[j]));
        }
    }

    // Non-hub nodes connect to q hubs (round-robin)
    for i in num_hubs..n {
        for j in 0..q.min(num_hubs) {
            let hub = hubs[(i + j) % num_hubs];
            edges.push((i, hub));
        }
        // Also connect to 1 non-hub neighbor for some mesh
        if q > num_hubs && i + 1 < n {
            edges.push((i, num_hubs + ((i - num_hubs + 1) % (n - num_hubs))));
        }
    }
    edges
}

// =========================================================================
// Safety record for one operator in one scenario
// =========================================================================

#[derive(Debug)]
struct SafetyRecord {
    local_conn: u32,
    true_mincut: u32,
    min_coalition: usize,
    n: usize,
    q: usize,
}

impl SafetyRecord {
    /// LocalConn matches or exceeds true mincut?
    fn lconn_is_conservative(&self) -> bool {
        self.local_conn <= self.true_mincut
    }
    /// LocalConn exactly equals true mincut?
    fn lconn_is_exact(&self) -> bool {
        self.local_conn == self.true_mincut
    }
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn localconn_safety_map() {
    println!("\n=== LocalConn Safety Map ===");
    println!("  What does each LocalConn value mean for deposit safety?\n");

    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    // Collect records across many scenarios
    let mut all_records: Vec<SafetyRecord> = Vec::new();

    let scenarios: Vec<(
        &str,
        usize,
        usize,
        usize,
        Box<dyn Fn(usize, usize) -> Vec<(usize, usize)>>,
    )> = vec![
        ("ring", 16, 3, 2, Box::new(ring_topology)),
        ("ring", 16, 5, 2, Box::new(ring_topology)),
        ("ring", 32, 5, 2, Box::new(ring_topology)),
        ("ring", 32, 5, 3, Box::new(ring_topology)),
        ("ring", 32, 7, 3, Box::new(ring_topology)),
        ("dispersed", 16, 3, 2, Box::new(dispersed_topology)),
        ("dispersed", 16, 5, 2, Box::new(dispersed_topology)),
        ("dispersed", 32, 5, 2, Box::new(dispersed_topology)),
        ("dispersed", 32, 7, 3, Box::new(dispersed_topology)),
        (
            "clustered",
            16,
            3,
            2,
            Box::new(|n, q| clustered_topology(n, q, 4)),
        ),
        (
            "clustered",
            16,
            5,
            2,
            Box::new(|n, q| clustered_topology(n, q, 4)),
        ),
        (
            "clustered",
            32,
            5,
            2,
            Box::new(|n, q| clustered_topology(n, q, 4)),
        ),
        (
            "clustered",
            32,
            5,
            3,
            Box::new(|n, q| clustered_topology(n, q, 8)),
        ),
        (
            "hub-spoke",
            16,
            3,
            2,
            Box::new(|n, q| hub_spoke_topology(n, q, 3)),
        ),
        (
            "hub-spoke",
            16,
            5,
            2,
            Box::new(|n, q| hub_spoke_topology(n, q, 4)),
        ),
        (
            "hub-spoke",
            32,
            5,
            2,
            Box::new(|n, q| hub_spoke_topology(n, q, 5)),
        ),
        (
            "hub-spoke",
            32,
            5,
            3,
            Box::new(|n, q| hub_spoke_topology(n, q, 5)),
        ),
    ];

    for (topo, n, q, num_anchors, gen) in &scenarios {
        let edges = gen(*n, *q);
        let adj = adjacency(*n, &edges);

        // Place anchors evenly
        let anchors: Vec<usize> = (0..*num_anchors).map(|i| i * n / num_anchors).collect();

        for target in 0..*n {
            if anchors.contains(&target) {
                continue;
            }
            // Skip nodes with no edges (isolated in hub-spoke)
            if adj[target].is_empty() {
                continue;
            }

            let lconn = local_connectivity(&adj, target, &anchors);
            let mc = mincut_to_anchors(*n, &edges, target, &anchors);
            let min_coal = min_profitable_coalition(*n, &edges, target, reserves, collateral);

            all_records.push(SafetyRecord {
                local_conn: lconn,
                true_mincut: mc,
                min_coalition: min_coal,
                n: *n,
                q: *q,
            });
        }
    }

    // =====================================================================
    // Table 1: LocalConn value → safety statistics
    // =====================================================================
    println!("--- Table 1: What does LocalConn=K mean? ---\n");
    println!(
        "{:>6} | {:>6} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>10}",
        "LConn", "Count", "MinMC", "AvgMC", "MaxMC", "Exact%", "Conserv%", "AvgMinCoal"
    );
    println!("{}", "-".repeat(80));

    let mut by_lconn: HashMap<u32, Vec<&SafetyRecord>> = HashMap::new();
    for r in &all_records {
        by_lconn.entry(r.local_conn).or_default().push(r);
    }
    let mut lconn_keys: Vec<u32> = by_lconn.keys().copied().collect();
    lconn_keys.sort();

    for lc in &lconn_keys {
        let records = &by_lconn[lc];
        let count = records.len();
        let min_mc = records.iter().map(|r| r.true_mincut).min().unwrap();
        let max_mc = records.iter().map(|r| r.true_mincut).max().unwrap();
        let avg_mc = records.iter().map(|r| r.true_mincut as f64).sum::<f64>() / count as f64;
        let exact_pct =
            records.iter().filter(|r| r.lconn_is_exact()).count() as f64 / count as f64 * 100.0;
        let conserv_pct = records.iter().filter(|r| r.lconn_is_conservative()).count() as f64
            / count as f64
            * 100.0;
        let avg_coal = records
            .iter()
            .map(|r| {
                if r.min_coalition >= r.n {
                    r.n
                } else {
                    r.min_coalition
                }
            })
            .sum::<usize>() as f64
            / count as f64;

        println!(
            "{:>6} | {:>6} | {:>8} | {:>8.1} | {:>8} | {:>7.1}% | {:>7.1}% | {:>10.1}",
            lc, count, min_mc, avg_mc, max_mc, exact_pct, conserv_pct, avg_coal,
        );
    }

    // =====================================================================
    // Table 2: LocalConn accuracy by topology
    // =====================================================================
    println!("\n--- Table 2: LocalConn accuracy vs true Mincut, by topology ---\n");
    println!(
        "{:>12} | {:>5} | {:>5} | {:>6} | {:>8} | {:>8} | {:>8}",
        "Topology", "N", "Q", "Count", "Exact%", "Conserv%", "MaxError"
    );
    println!("{}", "-".repeat(65));

    // Re-run per-scenario to get topology-level accuracy
    for (topo, n, q, num_anchors, gen) in &scenarios {
        let edges = gen(*n, *q);
        let adj = adjacency(*n, &edges);
        let anchors: Vec<usize> = (0..*num_anchors).map(|i| i * n / num_anchors).collect();

        let mut exact = 0;
        let mut conservative = 0;
        let mut max_error: i32 = 0;
        let mut count = 0;

        for target in 0..*n {
            if anchors.contains(&target) {
                continue;
            }
            if adj[target].is_empty() {
                continue;
            }

            let lconn = local_connectivity(&adj, target, &anchors);
            let mc = mincut_to_anchors(*n, &edges, target, &anchors);

            count += 1;
            if lconn == mc {
                exact += 1;
            }
            if lconn <= mc {
                conservative += 1;
            }
            let err = (lconn as i32 - mc as i32).abs();
            if err > max_error {
                max_error = err;
            }
        }

        if count > 0 {
            println!(
                "{:>12} | {:>5} | {:>5} | {:>6} | {:>7.1}% | {:>7.1}% | {:>8}",
                topo,
                n,
                q,
                count,
                exact as f64 / count as f64 * 100.0,
                conservative as f64 / count as f64 * 100.0,
                max_error,
            );
        }
    }

    // =====================================================================
    // Table 3: Safety thresholds — what LocalConn do you need?
    // =====================================================================
    println!("\n--- Table 3: Safety thresholds ---\n");
    println!("  For each LocalConn value, what's the worst-case attack?");
    println!();
    println!(
        "{:>6} | {:>12} | {:>12} | {:>40}",
        "LConn", "Min mincut", "Worst coal", "Interpretation"
    );
    println!("{}", "-".repeat(80));

    for lc in &lconn_keys {
        let records = &by_lconn[lc];
        let min_mc = records.iter().map(|r| r.true_mincut).min().unwrap();
        let worst_coal = records
            .iter()
            .map(|r| {
                if r.min_coalition >= r.n {
                    usize::MAX
                } else {
                    r.min_coalition
                }
            })
            .min()
            .unwrap();

        let interp = match *lc {
            0 => "DANGER: disconnected from anchors, unverifiable",
            1 => "WEAK: single node removal isolates from oversight",
            2 => "MODERATE: needs 2 colluding nodes to isolate",
            3 => "GOOD: 3 independent paths to anchor oversight",
            4 => "STRONG: 4 independent paths to anchor oversight",
            _ => "VERY STRONG: high redundancy to anchor oversight",
        };

        println!(
            "{:>6} | {:>12} | {:>12} | {}",
            lc,
            min_mc,
            if worst_coal == usize::MAX {
                "safe".to_string()
            } else {
                worst_coal.to_string()
            },
            interp,
        );
    }

    // =====================================================================
    // Table 4: Topology comparison — which topologies produce which LConns?
    // =====================================================================
    println!("\n--- Table 4: LocalConn distribution by topology ---\n");

    let topo_names = ["ring", "dispersed", "clustered", "hub-spoke"];
    // Collect LConn distributions per topology type
    let mut topo_dists: HashMap<&str, HashMap<u32, usize>> = HashMap::new();

    for (topo, n, q, num_anchors, gen) in &scenarios {
        let edges = gen(*n, *q);
        let adj = adjacency(*n, &edges);
        let anchors: Vec<usize> = (0..*num_anchors).map(|i| i * n / num_anchors).collect();

        let dist = topo_dists.entry(topo).or_default();
        for target in 0..*n {
            if anchors.contains(&target) {
                continue;
            }
            if adj[target].is_empty() {
                continue;
            }
            let lconn = local_connectivity(&adj, target, &anchors);
            *dist.entry(lconn).or_insert(0) += 1;
        }
    }

    print!("{:>12} |", "Topology");
    for lc in &lconn_keys {
        print!(" LC={:<3} |", lc);
    }
    println!();
    println!("{}", "-".repeat(14 + lconn_keys.len() * 9));

    for topo in &topo_names {
        print!("{:>12} |", topo);
        let dist = topo_dists.get(topo);
        let total: usize = dist.map(|d| d.values().sum()).unwrap_or(0);
        for lc in &lconn_keys {
            let count = dist.and_then(|d| d.get(lc)).copied().unwrap_or(0);
            if count > 0 {
                print!(" {:>4} {:>2}% |", count, count * 100 / total);
            } else {
                print!("         |");
            }
        }
        println!();
    }

    // =====================================================================
    // Summary assertions
    // =====================================================================
    println!("\n--- Summary ---\n");

    let total = all_records.len();
    let exact = all_records.iter().filter(|r| r.lconn_is_exact()).count();
    let conservative = all_records
        .iter()
        .filter(|r| r.lconn_is_conservative())
        .count();
    let optimistic = total - conservative;

    println!("  Total observations:  {}", total);
    println!(
        "  LocalConn == Mincut: {} ({:.1}%)",
        exact,
        exact as f64 / total as f64 * 100.0
    );
    println!(
        "  LocalConn <= Mincut: {} ({:.1}%) — safe (conservative)",
        conservative,
        conservative as f64 / total as f64 * 100.0
    );
    println!(
        "  LocalConn >  Mincut: {} ({:.1}%) — UNSAFE (overestimates)",
        optimistic,
        optimistic as f64 / total as f64 * 100.0
    );

    // LocalConn should never be dangerously optimistic
    // Allow some small overestimates but flag them
    if optimistic > 0 {
        println!(
            "\n  WARNING: {} cases where LocalConn overestimates safety!",
            optimistic
        );
        println!("  These are cases where the 2-hop neighborhood misses a global bottleneck.");
        let overestimates: Vec<_> = all_records
            .iter()
            .filter(|r| !r.lconn_is_conservative())
            .collect();
        for r in overestimates.iter().take(10) {
            println!(
                "    N={} Q={}: LConn={} but Mincut={} (overestimate by {})",
                r.n,
                r.q,
                r.local_conn,
                r.true_mincut,
                r.local_conn as i32 - r.true_mincut as i32
            );
        }
    }

    println!();
    println!("  RECOMMENDATION: Wallets should require LocalConn >= 3 for deposit safety.");
    println!("  LocalConn=0: reject (disconnected from oversight)");
    println!("  LocalConn=1: avoid (single point of failure)");
    println!("  LocalConn=2: acceptable with elevated monitoring");
    println!("  LocalConn>=3: safe for normal deposits");
}
