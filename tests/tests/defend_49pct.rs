//! Can honest topology + wallet metrics survive 49% attack?
//!
//! Rules:
//!   - N=100, Q=5, 6 anchors (trusted, cannot be compromised)
//!   - Attacker controls 49 non-anchor nodes
//!   - Honest nodes choose their topology to maximize safety
//!   - Wallet chooses its acceptance metric
//!
//! Question: is there a (topology, metric) pair where 49% can't profit?

use std::collections::{HashSet, VecDeque};

struct FG { n: usize, c: Vec<Vec<u32>> }
impl FG {
    fn new(n: usize) -> Self { Self { n, c: vec![vec![0; n]; n] } }
    fn ae(&mut self, f: usize, t: usize, c: u32) { self.c[f][t] += c; }
    fn mf(&self, s: usize, t: usize) -> u32 {
        let n = self.n; let mut r = self.c.clone(); let mut tot = 0;
        loop {
            let mut p = vec![None; n]; let mut v = vec![false; n]; v[s] = true;
            let mut q = VecDeque::new(); q.push_back(s);
            while let Some(u) = q.pop_front() {
                if u == t { break; }
                for w in 0..n { if !v[w] && r[u][w] > 0 { v[w] = true; p[w] = Some(u); q.push_back(w); } }
            }
            if !v[t] { break; }
            let mut f = u32::MAX; let mut w = t;
            while let Some(u) = p[w] { f = f.min(r[u][w]); w = u; } w = t;
            while let Some(u) = p[w] { r[u][w] -= f; r[w][u] += f; w = u; } tot += f;
        }
        tot
    }
}

fn quorum_mincut(n: usize, adj: &[HashSet<usize>], quorum: &[usize], anchors: &[usize]) -> u32 {
    let src = n; let sink = n + 1; let nn = 2 * (n + 2);
    let mut g = FG::new(nn);
    let qs: HashSet<usize> = quorum.iter().copied().collect();
    let ans: HashSet<usize> = anchors.iter().copied().collect();
    for i in 0..n {
        let cap = if qs.contains(&i) || ans.contains(&i) { (n+1) as u32 } else { 1 };
        g.ae(2*i, 2*i+1, cap);
    }
    g.ae(2*src, 2*src+1, (n+1) as u32);
    g.ae(2*sink, 2*sink+1, (n+1) as u32);
    for i in 0..n { for &j in &adj[i] { g.ae(2*i+1, 2*j, (n+1) as u32); } }
    for &q in quorum { g.ae(2*src+1, 2*q, (n+1) as u32); }
    for &a in anchors { g.ae(2*a+1, 2*sink, (n+1) as u32); }
    g.mf(2*src+1, 2*sink)
}

// =========================================================================
// Topology builders
// =========================================================================

const N: usize = 100;
const Q: usize = 5;
const UTXO: u64 = 600_000;
const DEPOSIT: u64 = 100_000;

fn anchors() -> Vec<usize> { vec![0, 16, 33, 50, 66, 83] }

/// Topology 1: Simple ring (Q=5 adjacent neighbors)
fn topo_ring() -> Vec<Vec<usize>> {
    (0..N).map(|i| (1..=Q).map(|j| (i + j) % N).collect()).collect()
}

/// Topology 2: Dispersed — each node picks Q members spread across the ring
fn topo_dispersed() -> Vec<Vec<usize>> {
    (0..N).map(|i| {
        let stride = N / (Q + 1);
        (1..=Q).map(|j| (i + j * stride) % N).collect()
    }).collect()
}

/// Topology 3: Anchor-seeded — each node has 1 anchor + 4 dispersed members
fn topo_anchor_seeded() -> Vec<Vec<usize>> {
    let anch = anchors();
    (0..N).map(|i| {
        // Closest anchor that isn't self
        let nearest_anchor = anch.iter()
            .filter(|&&a| a != i)
            .min_by_key(|&&a| {
                let d = if a > i { a - i } else { i - a };
                d.min(N - d)
            })
            .copied().unwrap();
        let stride = N / (Q + 1);
        let mut members = vec![nearest_anchor];
        for j in 1..=Q {
            let m = (i + j * stride) % N;
            if m != i && m != nearest_anchor && !members.contains(&m) {
                members.push(m);
            }
            if members.len() >= Q { break; }
        }
        // Fill if needed
        let mut j = 1;
        while members.len() < Q {
            let m = (i + j) % N;
            if m != i && !members.contains(&m) { members.push(m); }
            j += 1;
        }
        members.truncate(Q);
        members
    }).collect()
}

/// Topology 4: Multi-anchor — each node has 2 different anchors + 3 dispersed
fn topo_multi_anchor() -> Vec<Vec<usize>> {
    let anch = anchors();
    (0..N).map(|i| {
        // Two closest anchors
        let mut sorted_anchors: Vec<usize> = anch.iter()
            .filter(|&&a| a != i)
            .copied().collect();
        sorted_anchors.sort_by_key(|&a| {
            let d = if a > i { a - i } else { i - a };
            d.min(N - d)
        });
        let mut members: Vec<usize> = sorted_anchors.iter().take(2).copied().collect();
        // 3 dispersed
        let stride = N / 4;
        for j in 1..=3 {
            let m = (i + j * stride) % N;
            if m != i && !members.contains(&m) {
                members.push(m);
            }
        }
        let mut j = 1;
        while members.len() < Q {
            let m = (i + j) % N;
            if m != i && !members.contains(&m) { members.push(m); }
            j += 1;
        }
        members.truncate(Q);
        members
    }).collect()
}

/// Topology 5: All-anchor — every quorum has 3 anchors + 2 dispersed (majority anchor)
fn topo_anchor_majority() -> Vec<Vec<usize>> {
    let anch = anchors();
    (0..N).map(|i| {
        let mut sorted_anchors: Vec<usize> = anch.iter()
            .filter(|&&a| a != i)
            .copied().collect();
        sorted_anchors.sort_by_key(|&a| {
            let d = if a > i { a - i } else { i - a };
            d.min(N - d)
        });
        let mut members: Vec<usize> = sorted_anchors.iter().take(3).copied().collect();
        let stride = N / 3;
        for j in 1..=2 {
            let m = (i + j * stride) % N;
            if m != i && !members.contains(&m) {
                members.push(m);
            }
        }
        let mut j = 1;
        while members.len() < Q {
            let m = (i + j) % N;
            if m != i && !members.contains(&m) { members.push(m); }
            j += 1;
        }
        members.truncate(Q);
        members
    }).collect()
}

fn build_adj(quorums: &[Vec<usize>]) -> Vec<HashSet<usize>> {
    let n = quorums.len();
    let mut adj = vec![HashSet::new(); n];
    for i in 0..n {
        for &m in &quorums[i] {
            adj[i].insert(m);
            adj[m].insert(i);
        }
    }
    adj
}

// =========================================================================
// Attack simulation
// =========================================================================

struct AttackResult {
    wallet_loss: u64,
    attacker_cost: u64,
    net: i64,
    stolen_from_honest: u64,
    stolen_from_attacker: u64,
    safe_on_attacker: u64,
}

fn simulate(quorums: &[Vec<usize>], attackers: &HashSet<usize>, deposits: &[u64], per_lock: u64) -> AttackResult {
    let n = quorums.len();
    let mut wallet_loss = 0u64;
    let mut attacker_cost = 0u64;
    let mut stolen_honest = 0u64;
    let mut stolen_attacker = 0u64;
    let mut safe_attacker = 0u64;

    for i in 0..n {
        let q = &quorums[i];
        let ciq = q.iter().filter(|m| attackers.contains(m)).count();
        let hiq = q.len() - ciq;
        let maj = (q.len() + 1) / 2;
        let hmaj = hiq >= maj;
        let is_att = attackers.contains(&i);

        if is_att {
            if hmaj {
                attacker_cost += UTXO / 2; // reserves confiscated
                if deposits[i] > 0 { safe_attacker += deposits[i]; }
            } else if deposits[i] > 0 {
                wallet_loss += deposits[i];
                stolen_attacker += deposits[i];
            }
        } else {
            if !hmaj && deposits[i] > 0 {
                wallet_loss += deposits[i];
                stolen_honest += deposits[i];
            } else if hmaj && ciq > 0 {
                attacker_cost += ciq as u64 * per_lock;
            }
        }
    }

    AttackResult {
        wallet_loss, attacker_cost,
        net: wallet_loss as i64 - attacker_cost as i64,
        stolen_from_honest: stolen_honest,
        stolen_from_attacker: stolen_attacker,
        safe_on_attacker: safe_attacker,
    }
}

/// Generate attacker placements: adjacent block at every starting position.
fn best_adjacent_attack(quorums: &[Vec<usize>], count: usize, anch: &[usize], deposits: &[u64], per_lock: u64) -> AttackResult {
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();
    let mut best: Option<AttackResult> = None;

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
        let result = simulate(quorums, &attackers, deposits, per_lock);
        if best.as_ref().map_or(true, |b| result.net > b.net) {
            best = Some(result);
        }
    }
    best.unwrap()
}

/// Spread attack: every other non-anchor node
fn spread_attack(quorums: &[Vec<usize>], count: usize, anch: &[usize], deposits: &[u64], per_lock: u64) -> AttackResult {
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();
    let non_anchor: Vec<usize> = (0..N).filter(|i| !anchor_set.contains(i)).collect();
    let mut attackers = HashSet::new();
    // Every other
    for (idx, &node) in non_anchor.iter().enumerate() {
        if attackers.len() >= count { break; }
        if idx % 2 == 0 { attackers.insert(node); }
    }
    // Fill remainder
    for &node in &non_anchor {
        if attackers.len() >= count { break; }
        attackers.insert(node);
    }
    simulate(quorums, &attackers, deposits, per_lock)
}

#[test]
fn defend_49_percent() {
    let anch = anchors();
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();
    let per_lock = UTXO / (2 * Q as u64);

    println!("\n=== DEFEND AGAINST 49%: N={}, Q={}, 6 trusted anchors ===\n", N, Q);

    let topologies: Vec<(&str, Vec<Vec<usize>>)> = vec![
        ("ring", topo_ring()),
        ("dispersed", topo_dispersed()),
        ("anchor-seeded", topo_anchor_seeded()),
        ("multi-anchor", topo_multi_anchor()),
        ("anchor-majority", topo_anchor_majority()),
    ];

    println!("{:>18} | {:>7} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>12}",
        "Topology", "Attack", "W.Loss", "Atk.Cost", "Net", "FromHonest", "FromAtk", "SafeOnAtk");
    println!("{}", "-".repeat(110));

    for (name, quorums) in &topologies {
        let adj = build_adj(quorums);

        // Compute quorum-mincut stats
        let qmcs: Vec<u32> = (0..N)
            .filter(|i| !anchor_set.contains(i))
            .map(|i| quorum_mincut(N, &adj, &quorums[i], &anch))
            .collect();
        let min_qmc = qmcs.iter().min().unwrap();
        let max_qmc = qmcs.iter().max().unwrap();

        // Wallet deposits on all nodes passing quorum-mincut >= min_qmc
        let mut deposits = vec![0u64; N];
        for i in 0..N {
            if anchor_set.contains(&i) { continue; }
            let qmc = quorum_mincut(N, &adj, &quorums[i], &anch);
            if qmc >= *min_qmc {
                deposits[i] = DEPOSIT;
            }
        }

        let total_deposited: u64 = deposits.iter().sum();

        // Count how many anchors each quorum has
        let anchor_counts: Vec<usize> = (0..N)
            .filter(|i| !anchor_set.contains(i))
            .map(|i| quorums[i].iter().filter(|&&m| anchor_set.contains(&m)).count())
            .collect();
        let min_anchor_q = anchor_counts.iter().min().unwrap();

        println!("  {} — qmc=[{},{}], anchors_in_quorum=[{},{}], deposited={}",
            name, min_qmc, max_qmc,
            min_anchor_q, anchor_counts.iter().max().unwrap(),
            total_deposited);

        // Attack 1: best adjacent block
        let adj_result = best_adjacent_attack(quorums, 49, &anch, &deposits, per_lock);
        println!("{:>18} | {:>7} | {:>10} | {:>10} | {:>+10} | {:>10} | {:>10} | {:>12}",
            name, "adj49",
            adj_result.wallet_loss, adj_result.attacker_cost, adj_result.net,
            adj_result.stolen_from_honest, adj_result.stolen_from_attacker, adj_result.safe_on_attacker);

        // Attack 2: spread
        let spr_result = spread_attack(quorums, 49, &anch, &deposits, per_lock);
        println!("{:>18} | {:>7} | {:>10} | {:>10} | {:>+10} | {:>10} | {:>10} | {:>12}",
            "", "spr49",
            spr_result.wallet_loss, spr_result.attacker_cost, spr_result.net,
            spr_result.stolen_from_honest, spr_result.stolen_from_attacker, spr_result.safe_on_attacker);

        // Attack 3: smaller adjacent (30%)
        let adj30 = best_adjacent_attack(quorums, 28, &anch, &deposits, per_lock);
        println!("{:>18} | {:>7} | {:>10} | {:>10} | {:>+10} | {:>10} | {:>10} | {:>12}",
            "", "adj30%",
            adj30.wallet_loss, adj30.attacker_cost, adj30.net,
            adj30.stolen_from_honest, adj30.stolen_from_attacker, adj30.safe_on_attacker);

        println!();
    }
}
