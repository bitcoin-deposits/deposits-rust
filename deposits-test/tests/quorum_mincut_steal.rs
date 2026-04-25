//! Can we steal from wallets that enforce quorum-mincut?
//!
//! Wallet policy: compute mincut({operator's quorum members}, {my anchors}).
//! Only deposit if quorum-mincut >= threshold.
//! Try every attack strategy to extract wallet deposits profitably.

use std::collections::{HashSet, VecDeque};

// =========================================================================
// Flow graph
// =========================================================================

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

fn quorum_mincut(n: usize, adj: &[HashSet<usize>], quorum: &[usize], anchors: &[usize]) -> u32 {
    let src = n;
    let sink = n + 1;
    let nn = 2 * (n + 2);
    let mut g = FG::new(nn);
    let qs: HashSet<usize> = quorum.iter().copied().collect();
    let ans: HashSet<usize> = anchors.iter().copied().collect();
    for i in 0..n {
        let cap = if qs.contains(&i) || ans.contains(&i) {
            (n + 1) as u32
        } else {
            1
        };
        g.ae(2 * i, 2 * i + 1, cap);
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
// Network
// =========================================================================

struct Network {
    adj: Vec<HashSet<usize>>,
    quorum: Vec<Vec<usize>>,
    is_attacker: Vec<bool>,
    reserves: Vec<u64>,
    per_lock: Vec<u64>,
    deposits: Vec<u64>,
    anchors: Vec<usize>,
    labels: Vec<String>,
}

impl Network {
    fn honest_ring(n: usize, q: usize, num_anchors: usize, utxo: u64) -> Self {
        let reserves = utxo / 2;
        let per_lock = utxo / (2 * q as u64);
        let mut adj = vec![HashSet::new(); n];
        let quorum: Vec<Vec<usize>> = (0..n)
            .map(|i| (1..=q).map(|j| (i + j) % n).collect())
            .collect();
        for i in 0..n {
            for &m in &quorum[i] {
                adj[i].insert(m);
                adj[m].insert(i);
            }
        }
        let anchors: Vec<usize> = (0..num_anchors).map(|i| i * n / num_anchors).collect();
        let labels = (0..n).map(|i| format!("h{}", i)).collect();
        Network {
            adj,
            quorum,
            is_attacker: vec![false; n],
            reserves: vec![reserves; n],
            per_lock: vec![per_lock; n],
            deposits: vec![0; n],
            anchors,
            labels,
        }
    }

    fn n(&self) -> usize {
        self.adj.len()
    }

    fn add_node(&mut self, label: &str, is_attacker: bool, reserves: u64, per_lock: u64) -> usize {
        let id = self.n();
        self.adj.push(HashSet::new());
        self.quorum.push(Vec::new());
        self.is_attacker.push(is_attacker);
        self.reserves.push(reserves);
        self.per_lock.push(per_lock);
        self.deposits.push(0);
        self.labels.push(label.to_string());
        id
    }

    fn add_quorum_edge(&mut self, operator: usize, member: usize) {
        if !self.quorum[operator].contains(&member) {
            self.quorum[operator].push(member);
        }
        self.adj[operator].insert(member);
        self.adj[member].insert(operator);
    }

    fn compromise(&mut self, node: usize) {
        self.is_attacker[node] = true;
    }

    fn wallet_check(&self, operator: usize, threshold: u32) -> (bool, u32) {
        let qmc = quorum_mincut(self.n(), &self.adj, &self.quorum[operator], &self.anchors);
        (qmc >= threshold, qmc)
    }

    fn wallet_deposit_all(&mut self, amount: u64, threshold: u32) -> Vec<usize> {
        let mut deposited = Vec::new();
        for i in 0..self.n() {
            if self.anchors.contains(&i) {
                continue;
            }
            if self.quorum[i].is_empty() {
                continue;
            }
            let (ok, _) = self.wallet_check(i, threshold);
            if ok {
                self.deposits[i] += amount;
                deposited.push(i);
            }
        }
        deposited
    }

    fn attack(&self) -> AttackOutcome {
        let n = self.n();
        let cs: HashSet<usize> = (0..n).filter(|&i| self.is_attacker[i]).collect();
        let mut wallet_loss = 0u64;
        let mut attacker_cost = 0u64;
        let mut details = Vec::new();

        for i in 0..n {
            let q = &self.quorum[i];
            if q.is_empty() {
                continue;
            }
            let ciq = q.iter().filter(|m| cs.contains(m)).count();
            let hiq = q.len() - ciq;
            let maj = q.len().div_ceil(2);
            let hmaj = hiq >= maj;
            let is_att = self.is_attacker[i];

            if is_att {
                if hmaj {
                    attacker_cost += self.reserves[i];
                    if self.deposits[i] > 0 {
                        details.push(format!(
                            "  {}: ATK, deposits {} SAFE (honest quorum {}h/{})",
                            self.labels[i],
                            self.deposits[i],
                            hiq,
                            q.len()
                        ));
                    }
                } else if self.deposits[i] > 0 {
                    wallet_loss += self.deposits[i];
                    details.push(format!(
                        "  {}: ATK steals deposit {}! (coal {}/{})",
                        self.labels[i],
                        self.deposits[i],
                        ciq,
                        q.len()
                    ));
                }
            } else {
                if !hmaj {
                    if self.deposits[i] > 0 {
                        wallet_loss += self.deposits[i];
                        details.push(format!(
                            "  {}: HONEST compromised, deposit {} stolen (coal {}/{})",
                            self.labels[i],
                            self.deposits[i],
                            ciq,
                            q.len()
                        ));
                    }
                } else if ciq > 0 {
                    let slashed: u64 = cs
                        .iter()
                        .filter(|&&c| q.contains(&c))
                        .map(|&c| self.per_lock[c])
                        .sum();
                    attacker_cost += slashed;
                    if slashed > 0 {
                        details.push(format!(
                            "  {}: HONEST safe, slashes {} ({} attacker members)",
                            self.labels[i], slashed, ciq
                        ));
                    }
                }
            }
        }
        AttackOutcome {
            wallet_loss,
            attacker_cost,
            net: wallet_loss as i64 - attacker_cost as i64,
            details,
        }
    }
}

struct AttackOutcome {
    wallet_loss: u64,
    attacker_cost: u64,
    net: i64,
    details: Vec<String>,
}

impl AttackOutcome {
    fn print(&self, label: &str) {
        let tag = if self.net > 0 { "STOLEN!" } else { "FAILED" };
        println!(
            "  [{}] {} — wallet_loss={} attacker_cost={} net={:+}",
            tag, label, self.wallet_loss, self.attacker_cost, self.net
        );
        if self.net > 0 || !self.details.is_empty() {
            for d in &self.details {
                println!("    {}", d);
            }
        }
    }
}

const THRESHOLD: u32 = 20; // we'll calibrate this
const UTXO: u64 = 600_000;
const Q: usize = 5;
const DEPOSIT: u64 = 100_000;

#[test]
fn try_to_steal_with_quorum_mincut() {
    println!("\n=== STEAL TEST: quorum-mincut policy ===\n");

    // First: find the right threshold by measuring honest network
    let base = Network::honest_ring(20, Q, 6, UTXO);
    let mut honest_qmcs: Vec<u32> = Vec::new();
    for i in 0..20 {
        if base.anchors.contains(&i) {
            continue;
        }
        let (_, qmc) = base.wallet_check(i, 0);
        honest_qmcs.push(qmc);
    }
    let min_honest_qmc = *honest_qmcs.iter().min().unwrap();
    println!(
        "Honest network quorum-mincut range: {} - {}",
        min_honest_qmc,
        honest_qmcs.iter().max().unwrap()
    );

    // Use a threshold that all honest nodes pass
    let threshold = min_honest_qmc;
    println!("Using threshold: {}\n", threshold);

    // =================================================================
    // Strategy 1: Pure sybil ring (the one that beat clustering)
    // =================================================================
    println!("=== Strategy 1: Sybil ring (20 sybils, 6 bridges) ===");
    {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let per_lock = UTXO / (2 * Q as u64);

        // Add sybil ring
        let mut sybil_ids = Vec::new();
        for i in 0..20 {
            let id = net.add_node(&format!("s{}", i), true, UTXO / 2, per_lock);
            sybil_ids.push(id);
        }
        // Internal ring quorums
        for i in 0..20 {
            for j in 1..=Q {
                net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + j) % 20]);
            }
        }
        // Bridges
        for (si, hi) in [(0, 1), (3, 4), (6, 7), (10, 11), (13, 14), (16, 17)] {
            net.add_quorum_edge(sybil_ids[si], hi);
        }

        // Check a sybil
        let (ok, qmc) = net.wallet_check(sybil_ids[8], threshold);
        println!("  sybil_8 quorum-mincut={}, passes={}", qmc, ok);

        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        let sybil_deps = sybil_ids.iter().filter(|i| deposited.contains(i)).count();
        println!(
            "  Deposited on {} nodes ({} sybils)",
            deposited.len(),
            sybil_deps
        );

        let outcome = net.attack();
        outcome.print("sybil ring");
    }
    println!();

    // =================================================================
    // Strategy 2: Sybil ring with MORE bridges (try to pump quorum-mincut)
    // =================================================================
    println!("=== Strategy 2: Sybil ring with max bridges ===");
    {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let per_lock = UTXO / (2 * Q as u64);

        let mut sybil_ids = Vec::new();
        for i in 0..20 {
            let id = net.add_node(&format!("s{}", i), true, UTXO / 2, per_lock);
            sybil_ids.push(id);
        }
        for i in 0..20 {
            for j in 1..=Q {
                net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + j) % 20]);
            }
        }
        // Bridge EVERY sybil to an honest node
        for i in 0..20 {
            let honest = if net.anchors.contains(&i) {
                (i + 1) % 20
            } else {
                i
            };
            net.add_quorum_edge(sybil_ids[i], honest);
        }

        let (ok, qmc) = net.wallet_check(sybil_ids[8], threshold);
        println!("  sybil_8 quorum-mincut={}, passes={}", qmc, ok);

        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        let sybil_deps = sybil_ids.iter().filter(|i| deposited.contains(i)).count();
        println!(
            "  Deposited on {} nodes ({} sybils)",
            deposited.len(),
            sybil_deps
        );

        if sybil_deps > 0 {
            let outcome = net.attack();
            outcome.print("max bridges");
        } else {
            println!("  No sybils accepted — attack impossible");
        }
    }
    println!();

    // =================================================================
    // Strategy 3: Add honest nodes to sybil quorums (give them dispute power)
    // =================================================================
    println!("=== Strategy 3: Sybils invite honest nodes into their quorums ===");
    {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let per_lock = UTXO / (2 * Q as u64);

        let mut sybil_ids = Vec::new();
        for i in 0..10 {
            let id = net.add_node(&format!("s{}", i), true, UTXO / 2, per_lock);
            sybil_ids.push(id);
        }
        // Each sybil gets 2 other sybils + 3 honest nodes as quorum
        // (this makes honest majority — the honest nodes CAN dispute!)
        for i in 0..10 {
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 1) % 10]);
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 2) % 10]);
            // 3 honest quorum members (spread out)
            net.add_quorum_edge(sybil_ids[i], (i * 2) % 20);
            net.add_quorum_edge(sybil_ids[i], (i * 2 + 1) % 20);
            net.add_quorum_edge(sybil_ids[i], (i * 2 + 5) % 20);
        }

        let (ok, qmc) = net.wallet_check(sybil_ids[0], threshold);
        println!("  sybil_0 quorum-mincut={}, passes={}", qmc, ok);
        println!(
            "  sybil_0 quorum={:?}",
            net.quorum[sybil_ids[0]]
                .iter()
                .map(|&m| net.labels[m].clone())
                .collect::<Vec<_>>()
        );

        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        let sybil_deps = sybil_ids.iter().filter(|i| deposited.contains(i)).count();
        println!(
            "  Deposited on {} nodes ({} sybils)",
            deposited.len(),
            sybil_deps
        );

        if sybil_deps > 0 {
            // But now honest nodes have dispute authority!
            let outcome = net.attack();
            outcome.print("honest quorum members");
        } else {
            println!("  No sybils accepted — attack impossible");
        }
    }
    println!();

    // =================================================================
    // Strategy 4: Compromise honest nodes embedded in the real network
    // =================================================================
    println!("=== Strategy 4: Compromise real nodes (adjacent) ===");
    for k in [2, 3, 4, 5, 6, 8, 10] {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        for i in 0..k.min(20) {
            let node = (1 + i) % 20;
            if !net.anchors.contains(&node) {
                net.compromise(node);
            }
        }
        let outcome = net.attack();
        outcome.print(&format!("{} adjacent compromised", k));
    }
    println!();

    // =================================================================
    // Strategy 5: Compromise an anchor + neighbors
    // =================================================================
    println!("=== Strategy 5: Compromised anchor + neighbors ===");
    {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        net.compromise(0); // anchor
        net.compromise(1);
        net.compromise(19);
        net.compromise(18);
        net.compromise(2);
        let outcome = net.attack();
        outcome.print("anchor + 4 neighbors");
    }
    println!();

    // =================================================================
    // Strategy 6: Large sybil ring with honest nodes woven in as quorum
    //             members, then compromise those honest nodes
    // =================================================================
    println!("=== Strategy 6: Sybils + compromise their honest quorum members ===");
    {
        let mut net = Network::honest_ring(20, Q, 6, UTXO);
        let per_lock = UTXO / (2 * Q as u64);

        let mut sybil_ids = Vec::new();
        for i in 0..10 {
            let id = net.add_node(&format!("s{}", i), true, UTXO / 2, per_lock);
            sybil_ids.push(id);
        }

        // Each sybil: 2 sybil quorum members + 3 honest (to pass quorum-mincut)
        let honest_in_quorum: Vec<Vec<usize>> = (0..10)
            .map(|i| vec![(i * 2) % 20, (i * 2 + 1) % 20, (i * 2 + 5) % 20])
            .collect();

        for i in 0..10 {
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 1) % 10]);
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 2) % 10]);
            for &h in &honest_in_quorum[i] {
                net.add_quorum_edge(sybil_ids[i], h);
            }
        }

        // Check before compromising
        let (ok, qmc) = net.wallet_check(sybil_ids[0], threshold);
        println!("  Before compromise: sybil_0 qmc={}, passes={}", qmc, ok);

        // Now compromise the honest quorum members too
        let all_honest_used: HashSet<usize> = honest_in_quorum.iter().flatten().copied().collect();
        println!(
            "  Compromising {} honest nodes used as quorum members: {:?}",
            all_honest_used.len(),
            all_honest_used
                .iter()
                .map(|h| format!("h{}", h))
                .collect::<Vec<_>>()
        );

        for &h in &all_honest_used {
            net.compromise(h);
        }

        // Wallet deposited BEFORE compromise (the attack is: pass check, then turn)
        let deposited = net.wallet_deposit_all(DEPOSIT, threshold);
        let sybil_deps = sybil_ids.iter().filter(|i| deposited.contains(i)).count();
        println!(
            "  Deposited on {} nodes ({} sybils)",
            deposited.len(),
            sybil_deps
        );

        if sybil_deps > 0 {
            let outcome = net.attack();
            outcome.print("sybils + compromised honest quorum");
        } else {
            println!("  No sybils accepted — attack impossible");
        }
    }
    println!();

    // =================================================================
    // Summary
    // =================================================================
    println!("=== SUMMARY ===");
    println!("  Wallet policy: quorum-mincut >= {}", threshold);
    println!("  Honest ring: 20 nodes, Q={}, 6 anchors", Q);
}

/// 100-node network, attacker controls 49 nodes. Can they profit?
#[test]
fn forty_nine_percent_attack() {
    let q = 5;
    let utxo = 600_000u64;
    let deposit = 100_000u64;
    let n = 100;
    let num_anchors = 6;

    println!("\n=== 49% ATTACK: 100 nodes, 49 attacker-controlled ===");
    println!("  Q={}, 6 anchors, 50/50 reserves/collateral\n", q);

    // Calibrate threshold from honest-only network
    let base = Network::honest_ring(n, q, num_anchors, utxo);
    let min_qmc = (0..n)
        .filter(|i| !base.anchors.contains(i) && !base.quorum[*i].is_empty())
        .map(|i| quorum_mincut(n, &base.adj, &base.quorum[i], &base.anchors))
        .min()
        .unwrap();
    let threshold = min_qmc;
    println!(
        "  Honest quorum-mincut minimum: {} (using as threshold)\n",
        threshold
    );

    // -----------------------------------------------------------------
    // Strategy A: 49 adjacent compromised nodes
    // -----------------------------------------------------------------
    println!("=== A: 49 adjacent compromised (nodes 1-49) ===");
    {
        let mut net = Network::honest_ring(n, q, num_anchors, utxo);
        net.wallet_deposit_all(deposit, threshold);
        for i in 1..50 {
            if !net.anchors.contains(&i) {
                net.compromise(i);
            }
        }

        let coal_count = (0..n).filter(|&i| net.is_attacker[i]).count();
        let outcome = net.attack();
        println!(
            "  Coalition: {} nodes ({}%)",
            coal_count,
            coal_count * 100 / n
        );
        outcome.print("49 adjacent");
    }
    println!();

    // -----------------------------------------------------------------
    // Strategy B: 49 evenly spread compromised nodes
    // -----------------------------------------------------------------
    println!("=== B: 49 evenly spread compromised ===");
    {
        let mut net = Network::honest_ring(n, q, num_anchors, utxo);
        net.wallet_deposit_all(deposit, threshold);
        // Every other node (skip anchors)
        let mut compromised = 0;
        for i in 0..n {
            if compromised >= 49 {
                break;
            }
            if i % 2 == 1 && !net.anchors.contains(&i) {
                net.compromise(i);
                compromised += 1;
            }
        }
        // Fill remaining
        for i in 0..n {
            if compromised >= 49 {
                break;
            }
            if !net.is_attacker[i] && !net.anchors.contains(&i) {
                net.compromise(i);
                compromised += 1;
            }
        }

        let coal_count = (0..n).filter(|&i| net.is_attacker[i]).count();
        let outcome = net.attack();
        println!(
            "  Coalition: {} nodes ({}%)",
            coal_count,
            coal_count * 100 / n
        );
        outcome.print("49 spread");
    }
    println!();

    // -----------------------------------------------------------------
    // Strategy C: 49 nodes including all anchors
    // -----------------------------------------------------------------
    println!("=== C: 49 nodes including all 6 anchors ===");
    {
        let mut net = Network::honest_ring(n, q, num_anchors, utxo);
        net.wallet_deposit_all(deposit, threshold);
        // Compromise all anchors
        for &a in &net.anchors.clone() {
            net.compromise(a);
        }
        // Plus 43 more adjacent to anchor 0
        let mut compromised = num_anchors;
        for i in 1..n {
            if compromised >= 49 {
                break;
            }
            if !net.is_attacker[i] {
                net.compromise(i);
                compromised += 1;
            }
        }

        let coal_count = (0..n).filter(|&i| net.is_attacker[i]).count();
        let outcome = net.attack();
        println!(
            "  Coalition: {} nodes ({}%)",
            coal_count,
            coal_count * 100 / n
        );
        outcome.print("49 incl anchors");
    }
    println!();

    // -----------------------------------------------------------------
    // Strategy D: 30 sybils + 19 compromised honest (= 49 total attacker)
    //             Sybils use compromised honest as quorum members
    // -----------------------------------------------------------------
    println!("=== D: 30 sybils + 19 compromised honest = 49 attacker ===");
    {
        let mut net = Network::honest_ring(n, q, num_anchors, utxo);
        let per_lock = utxo / (2 * q as u64);

        // 30 sybil nodes
        let mut sybil_ids = Vec::new();
        for i in 0..30 {
            let id = net.add_node(&format!("s{}", i), true, utxo / 2, per_lock);
            sybil_ids.push(id);
        }

        // Compromise 19 honest nodes (spread out)
        let mut compromised_honest = Vec::new();
        for i in 0..19 {
            let node = 1 + i * 5; // every 5th, skip anchors
            let node = if net.anchors.contains(&node) {
                node + 1
            } else {
                node
            };
            if node < n && !net.is_attacker[node] {
                net.compromise(node);
                compromised_honest.push(node);
            }
        }

        // Each sybil: 2 sybil quorum + 3 compromised honest quorum
        for i in 0..30 {
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 1) % 30]);
            net.add_quorum_edge(sybil_ids[i], sybil_ids[(i + 2) % 30]);
            // Rotate through compromised honest nodes
            for j in 0..3 {
                let h = compromised_honest[(i * 3 + j) % compromised_honest.len()];
                net.add_quorum_edge(sybil_ids[i], h);
            }
        }

        let n_total = net.n();
        let coal_count = (0..n_total).filter(|&i| net.is_attacker[i]).count();
        println!(
            "  Total nodes: {}, coalition: {} ({}% of honest network)",
            n_total, coal_count, 49
        );

        // Check if sybils pass
        let (ok, qmc) = net.wallet_check(sybil_ids[0], threshold);
        println!("  sybil_0 quorum-mincut={}, passes={}", qmc, ok);
        println!(
            "  sybil_0 quorum: {:?}",
            net.quorum[sybil_ids[0]]
                .iter()
                .map(|&m| net.labels[m].clone())
                .collect::<Vec<_>>()
        );

        net.wallet_deposit_all(deposit, threshold);

        let sybil_deps = sybil_ids.iter().filter(|&&i| net.deposits[i] > 0).count();
        let honest_deps = (0..n).filter(|&i| net.deposits[i] > 0).count();
        println!(
            "  Wallet deposited on {} honest + {} sybil nodes",
            honest_deps, sybil_deps
        );

        let outcome = net.attack();
        outcome.print("30 sybils + 19 compromised");
    }
    println!();

    // -----------------------------------------------------------------
    // Strategy E: All 49 embedded (no sybils), optimally placed
    //             Half the network is the attacker, ring positions chosen
    //             to maximize quorum overlap
    // -----------------------------------------------------------------
    println!("=== E: 49 embedded, optimal placement (alternating) ===");
    {
        let mut net = Network::honest_ring(n, q, num_anchors, utxo);
        net.wallet_deposit_all(deposit, threshold);

        // Compromise every other non-anchor node
        let mut compromised = 0;
        for i in 0..n {
            if compromised >= 49 {
                break;
            }
            if !net.anchors.contains(&i) && i % 2 == 1 {
                net.compromise(i);
                compromised += 1;
            }
        }
        for i in 0..n {
            if compromised >= 49 {
                break;
            }
            if !net.anchors.contains(&i) && !net.is_attacker[i] {
                net.compromise(i);
                compromised += 1;
            }
        }

        let coal_count = (0..n).filter(|&i| net.is_attacker[i]).count();

        // Count deposits on attacker vs honest nodes
        let att_deposits: u64 = (0..n)
            .filter(|&i| net.is_attacker[i])
            .map(|i| net.deposits[i])
            .sum();
        let hon_deposits: u64 = (0..n)
            .filter(|&i| !net.is_attacker[i])
            .map(|i| net.deposits[i])
            .sum();
        println!("  Coalition: {} nodes", coal_count);
        println!(
            "  Deposits on attacker nodes: {}, honest nodes: {}",
            att_deposits, hon_deposits
        );

        let outcome = net.attack();
        outcome.print("49 alternating");

        // Show breakdown
        let att_stolen: u64 = (0..n)
            .filter(|&i| {
                net.is_attacker[i] && net.deposits[i] > 0 && {
                    let ciq = net.quorum[i]
                        .iter()
                        .filter(|&&m| net.is_attacker[m])
                        .count();
                    let maj = net.quorum[i].len().div_ceil(2);
                    ciq >= maj
                }
            })
            .map(|i| net.deposits[i])
            .sum();
        let hon_stolen: u64 = (0..n)
            .filter(|&i| {
                !net.is_attacker[i] && net.deposits[i] > 0 && {
                    let ciq = net.quorum[i]
                        .iter()
                        .filter(|&&m| net.is_attacker[m])
                        .count();
                    let maj = net.quorum[i].len().div_ceil(2);
                    ciq >= maj
                }
            })
            .map(|i| net.deposits[i])
            .sum();
        let att_safe: u64 = (0..n)
            .filter(|&i| {
                net.is_attacker[i] && net.deposits[i] > 0 && {
                    let ciq = net.quorum[i]
                        .iter()
                        .filter(|&&m| net.is_attacker[m])
                        .count();
                    let maj = net.quorum[i].len().div_ceil(2);
                    ciq < maj
                }
            })
            .map(|i| net.deposits[i])
            .sum();
        println!("    Stolen from attacker nodes: {}", att_stolen);
        println!("    Stolen from honest nodes: {}", hon_stolen);
        println!("    Safe on attacker nodes (honest quorum): {}", att_safe);
    }
    println!();

    println!("=== SUMMARY: 49% attack on 100-node network ===");
    println!("  If attacker cannot profit at 49%, the protocol is secure.");
}
