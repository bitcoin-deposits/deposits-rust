//! What wallet-computable metric on quorum structure predicts safety?
//!
//! The wallet can see the full quorum graph. It can't control topology.
//! Anchors are trusted but won't necessarily be in quorums.
//! Test metrics that measure quorum diversity/spread.

use std::collections::{HashSet, VecDeque};

const N: usize = 100;
const Q: usize = 5;
const UTXO: u64 = 600_000;
const DEPOSIT: u64 = 100_000;

fn anchors() -> Vec<usize> {
    vec![0, 16, 33, 50, 66, 83]
}

// =========================================================================
// Topologies (what operators might choose)
// =========================================================================

fn topo_ring() -> Vec<Vec<usize>> {
    (0..N)
        .map(|i| (1..=Q).map(|j| (i + j) % N).collect())
        .collect()
}

fn topo_dispersed() -> Vec<Vec<usize>> {
    (0..N)
        .map(|i| {
            let stride = N / (Q + 1);
            (1..=Q).map(|j| (i + j * stride) % N).collect()
        })
        .collect()
}

/// Mixed: some operators use ring, some use dispersed
fn topo_mixed() -> Vec<Vec<usize>> {
    (0..N)
        .map(|i| {
            if i % 3 == 0 {
                // Ring-style
                (1..=Q).map(|j| (i + j) % N).collect()
            } else {
                // Dispersed
                let stride = N / (Q + 1);
                (1..=Q).map(|j| (i + j * stride) % N).collect()
            }
        })
        .collect()
}

fn build_adj(quorums: &[Vec<usize>]) -> Vec<HashSet<usize>> {
    let mut adj = vec![HashSet::new(); N];
    for i in 0..N {
        for &m in &quorums[i] {
            adj[i].insert(m);
            adj[m].insert(i);
        }
    }
    adj
}

// =========================================================================
// Candidate wallet metrics (computed per operator)
// =========================================================================

/// Metric 1: Quorum spread — average ring distance between quorum members.
/// Higher = members are more spread out.
fn quorum_spread(quorum: &[usize]) -> f64 {
    let mut total = 0.0;
    let mut pairs = 0;
    for i in 0..quorum.len() {
        for j in (i + 1)..quorum.len() {
            let d = ring_dist(quorum[i], quorum[j]);
            total += d as f64;
            pairs += 1;
        }
    }
    if pairs > 0 {
        total / pairs as f64
    } else {
        0.0
    }
}

fn ring_dist(a: usize, b: usize) -> usize {
    let d = a.abs_diff(b);
    d.min(N - d)
}

/// Metric 2: Min arc — smallest contiguous arc containing majority of quorum.
/// Lower = quorum is more clustered (vulnerable to adjacent attack).
fn min_majority_arc(quorum: &[usize]) -> usize {
    let majority = quorum.len().div_ceil(2);
    let mut positions: Vec<usize> = quorum.to_vec();
    positions.sort();

    let mut min_arc = N;
    // Try every subset of `majority` members, find the smallest arc
    for start_idx in 0..positions.len() {
        let end_idx = (start_idx + majority - 1) % positions.len();
        let arc = if end_idx >= start_idx {
            positions[end_idx] - positions[start_idx]
        } else {
            // Wraps around
            (N - positions[start_idx]) + positions[end_idx]
        };
        if arc < min_arc {
            min_arc = arc;
        }
    }
    min_arc
}

/// Metric 3: Anchor proximity — how many anchors are within `hops` of any quorum member?
fn anchor_reachable(
    adj: &[HashSet<usize>],
    quorum: &[usize],
    anchors: &[usize],
    max_hops: usize,
) -> usize {
    let anchor_set: HashSet<usize> = anchors.iter().copied().collect();
    let mut reached_anchors: HashSet<usize> = HashSet::new();

    for &start in quorum {
        // BFS from quorum member
        let mut visited = [false; N];
        let mut queue = VecDeque::new();
        visited[start] = true;
        queue.push_back((start, 0));
        while let Some((node, dist)) = queue.pop_front() {
            if anchor_set.contains(&node) {
                reached_anchors.insert(node);
            }
            if dist < max_hops {
                for &nb in &adj[node] {
                    if !visited[nb] {
                        visited[nb] = true;
                        queue.push_back((nb, dist + 1));
                    }
                }
            }
        }
    }
    reached_anchors.len()
}

/// Metric 4: Quorum mincut (the one we already have)
struct FG {
    n: usize,
    c: Vec<Vec<u32>>,
}
impl FG {
    fn new(n: usize) -> Self {
        Self {
            n,
            c: vec![vec![0; n]; n],
        }
    }
    fn ae(&mut self, f: usize, t: usize, c: u32) {
        self.c[f][t] += c;
    }
    fn mf(&self, s: usize, t: usize) -> u32 {
        let n = self.n;
        let mut r = self.c.clone();
        let mut tot = 0;
        loop {
            let mut p = vec![None; n];
            let mut v = vec![false; n];
            v[s] = true;
            let mut q = VecDeque::new();
            q.push_back(s);
            while let Some(u) = q.pop_front() {
                if u == t {
                    break;
                }
                for w in 0..n {
                    if !v[w] && r[u][w] > 0 {
                        v[w] = true;
                        p[w] = Some(u);
                        q.push_back(w);
                    }
                }
            }
            if !v[t] {
                break;
            }
            let mut f = u32::MAX;
            let mut w = t;
            while let Some(u) = p[w] {
                f = f.min(r[u][w]);
                w = u;
            }
            w = t;
            while let Some(u) = p[w] {
                r[u][w] -= f;
                r[w][u] += f;
                w = u;
            }
            tot += f;
        }
        tot
    }
}
fn qmc(adj: &[HashSet<usize>], quorum: &[usize], anchors: &[usize]) -> u32 {
    let n = N;
    let src = n;
    let sink = n + 1;
    let nn = 2 * (n + 2);
    let mut g = FG::new(nn);
    let qs: HashSet<usize> = quorum.iter().copied().collect();
    let ans: HashSet<usize> = anchors.iter().copied().collect();
    for i in 0..n {
        g.ae(
            2 * i,
            2 * i + 1,
            if qs.contains(&i) || ans.contains(&i) {
                (n + 1) as u32
            } else {
                1
            },
        );
    }
    g.ae(2 * src, 2 * src + 1, (n + 1) as u32);
    g.ae(2 * sink, 2 * sink + 1, (n + 1) as u32);
    for i in 0..n {
        for &j in &adj[i] {
            g.ae(2 * i + 1, 2 * j, (n + 1) as u32);
        }
    }
    for &q in quorum {
        g.ae(2 * src + 1, 2 * q, (n + 1) as u32);
    }
    for &a in anchors {
        g.ae(2 * a + 1, 2 * sink, (n + 1) as u32);
    }
    g.mf(2 * src + 1, 2 * sink)
}

// =========================================================================
// Attack simulation
// =========================================================================

fn best_adjacent_attack(
    quorums: &[Vec<usize>],
    count: usize,
    anch: &[usize],
    deposits: &[u64],
) -> i64 {
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();
    let per_lock = UTXO / (2 * Q as u64);
    let mut best_net = i64::MIN;
    for start in 0..N {
        let mut attackers = HashSet::new();
        let mut added = 0;
        let mut pos = start;
        while added < count {
            if !anchor_set.contains(&pos) {
                attackers.insert(pos);
                added += 1;
            }
            pos = (pos + 1) % N;
        }
        let mut wloss = 0u64;
        let mut acost = 0u64;
        for i in 0..N {
            let q = &quorums[i];
            let ciq = q.iter().filter(|m| attackers.contains(m)).count();
            let hiq = q.len() - ciq;
            let maj = q.len().div_ceil(2);
            let hmaj = hiq >= maj;
            let is_att = attackers.contains(&i);
            if is_att {
                if hmaj {
                    acost += UTXO / 2;
                } else if deposits[i] > 0 {
                    wloss += deposits[i];
                }
            } else {
                if !hmaj && deposits[i] > 0 {
                    wloss += deposits[i];
                } else if hmaj && ciq > 0 {
                    acost += ciq as u64 * per_lock;
                }
            }
        }
        let net = wloss as i64 - acost as i64;
        if net > best_net {
            best_net = net;
        }
    }
    best_net
}

#[test]
fn find_safe_metric() {
    let anch = anchors();
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();

    println!("\n=== QUORUM SPREAD: what metric predicts safety at 49%? ===");
    println!(
        "  N={}, Q={}, 6 trusted anchors, anchors NOT in quorums\n",
        N, Q
    );

    for (topo_name, quorums) in &[
        ("ring", topo_ring()),
        ("dispersed", topo_dispersed()),
        ("mixed", topo_mixed()),
    ] {
        let adj = build_adj(quorums);

        println!("=== Topology: {} ===\n", topo_name);

        // Compute all metrics for each non-anchor node
        println!(
            "{:>4} | {:>8} | {:>8} | {:>8} | {:>8} | {:>10}",
            "Node", "Spread", "MinArc", "AnchNear", "QMC", "Quorum"
        );
        println!("{}", "-".repeat(60));

        let mut spreads = Vec::new();
        let mut arcs = Vec::new();
        let mut anear = Vec::new();
        let mut qmcs = Vec::new();

        for i in 0..N {
            if anchor_set.contains(&i) {
                continue;
            }
            let sp = quorum_spread(&quorums[i]);
            let arc = min_majority_arc(&quorums[i]);
            let an = anchor_reachable(&adj, &quorums[i], &anch, 3);
            let qm = qmc(&adj, &quorums[i], &anch);

            spreads.push((i, sp));
            arcs.push((i, arc));
            anear.push((i, an));
            qmcs.push((i, qm));

            // Print first few and some middle ones
            if i < 5 || (48..=52).contains(&i) || i >= 95 {
                let qstr: String = quorums[i]
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{:>4} | {:>8.1} | {:>8} | {:>8} | {:>8} | [{}]",
                    i, sp, arc, an, qm, qstr
                );
            }
        }

        println!("  ...\n");

        // Metric ranges
        let sp_vals: Vec<f64> = spreads.iter().map(|x| x.1).collect();
        let arc_vals: Vec<usize> = arcs.iter().map(|x| x.1).collect();
        let an_vals: Vec<usize> = anear.iter().map(|x| x.1).collect();
        let qm_vals: Vec<u32> = qmcs.iter().map(|x| x.1).collect();

        println!(
            "  Spread:    [{:.1}, {:.1}]",
            sp_vals.iter().cloned().fold(f64::MAX, f64::min),
            sp_vals.iter().cloned().fold(0.0f64, f64::max)
        );
        println!(
            "  MinArc:    [{}, {}]",
            arc_vals.iter().min().unwrap(),
            arc_vals.iter().max().unwrap()
        );
        println!(
            "  AnchNear3: [{}, {}]",
            an_vals.iter().min().unwrap(),
            an_vals.iter().max().unwrap()
        );
        println!(
            "  QMC:       [{}, {}]",
            qm_vals.iter().min().unwrap(),
            qm_vals.iter().max().unwrap()
        );

        // Now test: for each metric threshold, how much can 49% adjacent steal?
        println!("\n  --- Sweep: wallet filters by metric, attacker tries adj49 ---\n");
        println!(
            "  {:>12} {:>10} | {:>8} | {:>10}",
            "Filter", "Threshold", "Accepted", "Adj49 net"
        );
        println!("  {}", "-".repeat(50));

        // Sweep spread thresholds
        for &thresh in &[0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0] {
            let mut deposits = vec![0u64; N];
            let mut accepted = 0;
            for i in 0..N {
                if anchor_set.contains(&i) {
                    continue;
                }
                if quorum_spread(&quorums[i]) >= thresh {
                    deposits[i] = DEPOSIT;
                    accepted += 1;
                }
            }
            if accepted == 0 {
                continue;
            }
            let net = best_adjacent_attack(quorums, 49, &anch, &deposits);
            let tag = if net > 0 { " STOLEN!" } else { "" };
            println!(
                "  {:>12} {:>10.0} | {:>8} | {:>+10}{}",
                "Spread>=", thresh, accepted, net, tag
            );
        }

        // Sweep min-arc thresholds
        for &thresh in &[0, 3, 5, 10, 15, 20, 25, 30] {
            let mut deposits = vec![0u64; N];
            let mut accepted = 0;
            for i in 0..N {
                if anchor_set.contains(&i) {
                    continue;
                }
                if min_majority_arc(&quorums[i]) >= thresh {
                    deposits[i] = DEPOSIT;
                    accepted += 1;
                }
            }
            if accepted == 0 {
                continue;
            }
            let net = best_adjacent_attack(quorums, 49, &anch, &deposits);
            let tag = if net > 0 { " STOLEN!" } else { "" };
            println!(
                "  {:>12} {:>10} | {:>8} | {:>+10}{}",
                "MinArc>=", thresh, accepted, net, tag
            );
        }

        // Sweep QMC thresholds
        for &thresh in &[0u32, 10, 20, 50, 100, 200] {
            let mut deposits = vec![0u64; N];
            let mut accepted = 0;
            for i in 0..N {
                if anchor_set.contains(&i) {
                    continue;
                }
                if qmc(&adj, &quorums[i], &anch) >= thresh {
                    deposits[i] = DEPOSIT;
                    accepted += 1;
                }
            }
            if accepted == 0 {
                continue;
            }
            let net = best_adjacent_attack(quorums, 49, &anch, &deposits);
            let tag = if net > 0 { " STOLEN!" } else { "" };
            println!(
                "  {:>12} {:>10} | {:>8} | {:>+10}{}",
                "QMC>=", thresh, accepted, net, tag
            );
        }

        println!();
    }
}
