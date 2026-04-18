//! Wallet safety advice: define a topology, check the metrics, try to steal.
//!
//! The wallet's job:
//!   1. Pick trust anchors (operators you know)
//!   2. Compute mincut from candidate operator to your anchors
//!   3. Require mincut >= threshold
//!   4. Deposit only if threshold met
//!
//! We build a realistic network, attach sybil islands, and try every attack.

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
        Self { n, capacity: vec![vec![0; n]; n] }
    }
    fn add_edge(&mut self, from: usize, to: usize, cap: u32) {
        self.capacity[from][to] += cap;
    }
    fn max_flow(&self, s: usize, t: usize) -> u32 {
        let n = self.n;
        let mut res = self.capacity.clone();
        let mut total = 0;
        loop {
            let mut parent = vec![None; n];
            let mut vis = vec![false; n];
            vis[s] = true;
            let mut q = VecDeque::new();
            q.push_back(s);
            while let Some(u) = q.pop_front() {
                if u == t { break; }
                for v in 0..n {
                    if !vis[v] && res[u][v] > 0 {
                        vis[v] = true;
                        parent[v] = Some(u);
                        q.push_back(v);
                    }
                }
            }
            if !vis[t] { break; }
            let mut flow = u32::MAX;
            let mut v = t;
            while let Some(u) = parent[v] { flow = flow.min(res[u][v]); v = u; }
            v = t;
            while let Some(u) = parent[v] { res[u][v] -= flow; res[v][u] += flow; v = u; }
            total += flow;
        }
        total
    }
}

fn mincut_to_anchors(n: usize, adj: &[Vec<usize>], target: usize, anchors: &[usize]) -> u32 {
    let ss = n;
    let nn = 2 * (n + 1);
    let mut g = FlowGraph::new(nn);
    for i in 0..n {
        let cap = if i == target { (n + 1) as u32 } else { 1 };
        g.add_edge(2 * i, 2 * i + 1, cap);
    }
    g.add_edge(2 * ss, 2 * ss + 1, (n + 1) as u32);
    for i in 0..n {
        for &j in &adj[i] {
            g.add_edge(2 * i + 1, 2 * j, (n + 1) as u32);
        }
    }
    for &a in anchors {
        g.add_edge(2 * a + 1, 2 * ss, (n + 1) as u32);
    }
    g.max_flow(2 * target + 1, 2 * ss)
}

// =========================================================================
// Network model
// =========================================================================

#[derive(Clone)]
struct Operator {
    id: usize,
    name: String,
    is_sybil: bool,
    reserves: u64,
    /// This operator's quorum members (who watches this ledger)
    quorum: Vec<usize>,
    /// Ledgers where this operator posts collateral (where they serve as quorum member)
    collateral_on: Vec<usize>,
    /// Per-lock collateral amount
    per_lock: u64,
}

struct Network {
    operators: Vec<Operator>,
    /// Adjacency list (bidirectional quorum relationships)
    adj: Vec<Vec<usize>>,
}

impl Network {
    /// Build a ring of `n` honest operators with quorum size `q`.
    /// Each operator: 50% reserves, 50% collateral split across q locks.
    fn ring(n: usize, q: usize, utxo_per_op: u64) -> Self {
        let reserves = utxo_per_op / 2;
        let per_lock = utxo_per_op / (2 * q as u64);

        let mut operators: Vec<Operator> = (0..n).map(|i| Operator {
            id: i,
            name: format!("honest_{}", i),
            is_sybil: false,
            reserves,
            quorum: (1..=q).map(|j| (i + j) % n).collect(),
            collateral_on: Vec::new(), // filled below
            per_lock,
        }).collect();

        // Each operator posts collateral on ledgers where they're a quorum member
        for i in 0..n {
            let posts_on: Vec<usize> = (0..n)
                .filter(|&j| operators[j].quorum.contains(&i))
                .collect();
            operators[i].collateral_on = posts_on;
        }

        let mut adj = vec![Vec::new(); n];
        for i in 0..n {
            for &m in &operators[i].quorum {
                if !adj[i].contains(&m) { adj[i].push(m); }
                if !adj[m].contains(&i) { adj[m].push(i); }
            }
        }

        Network { operators, adj }
    }

    /// Attach a sybil island: `num_sybils` fake nodes connected to `bridges`
    /// (existing honest nodes). Sybils form quorums among themselves.
    /// They post collateral on bridge nodes to create graph edges.
    fn attach_sybil_island(&mut self, num_sybils: usize, bridges: &[usize], q: usize, utxo_per_sybil: u64) {
        let base = self.operators.len();
        let reserves = utxo_per_sybil / 2;
        let per_lock = utxo_per_sybil / (2 * q as u64);

        // Create sybil operators
        for i in 0..num_sybils {
            let id = base + i;
            // Sybil quorum: other sybils + some bridges
            let mut quorum = Vec::new();
            for j in 1..=q {
                let m = base + ((i + j) % num_sybils);
                if m != id && !quorum.contains(&m) {
                    quorum.push(m);
                }
            }
            // If not enough sybils for full quorum, add bridges
            for &b in bridges {
                if quorum.len() >= q { break; }
                if !quorum.contains(&b) {
                    quorum.push(b);
                }
            }

            self.operators.push(Operator {
                id,
                name: format!("sybil_{}", i),
                is_sybil: true,
                reserves,
                quorum,
                collateral_on: Vec::new(),
                per_lock,
            });
        }

        // Sybils also join bridge nodes' quorums (to create edges)
        for (i, &bridge) in bridges.iter().enumerate() {
            let sybil_id = base + (i % num_sybils);
            if !self.operators[bridge].quorum.contains(&sybil_id) {
                self.operators[bridge].quorum.push(sybil_id);
            }
        }

        // Recalculate collateral_on for everyone
        let n = self.operators.len();
        for i in 0..n {
            let posts_on: Vec<usize> = (0..n)
                .filter(|&j| self.operators[j].quorum.contains(&i))
                .collect();
            self.operators[i].collateral_on = posts_on;
        }

        // Rebuild adjacency
        self.adj = vec![Vec::new(); n];
        for i in 0..n {
            for &m in &self.operators[i].quorum {
                if !self.adj[i].contains(&m) { self.adj[i].push(m); }
                if !self.adj[m].contains(&i) { self.adj[m].push(i); }
            }
        }
    }

    fn n(&self) -> usize { self.operators.len() }
}

// =========================================================================
// Attack simulation
// =========================================================================

struct AttackResult {
    target: usize,
    coalition: Vec<usize>,
    extracted: u64,
    slashed: u64,
    own_reserves_lost: u64,
    net: i64,
}

fn simulate_attack(net: &Network, target: usize, coalition: &[usize]) -> AttackResult {
    let cs: HashSet<usize> = coalition.iter().copied().collect();
    let n = net.operators.len();

    let mut extracted = 0u64;
    let mut slashed = 0u64;
    let mut own_lost = 0u64;

    for i in 0..n {
        let op = &net.operators[i];
        let q = &op.quorum;
        let ciq = q.iter().filter(|m| cs.contains(m)).count();
        let hiq = q.len() - ciq;
        let maj = (q.len() + 1) / 2;
        let hmaj = hiq >= maj;
        let is_c = cs.contains(&i);

        if i == target && ciq >= maj {
            extracted += op.reserves;
        } else if is_c {
            if hmaj {
                own_lost += op.reserves;
            }
            // else: coalition controls own quorum, walks away (but this is own money)
        } else if !is_c && !hmaj {
            // Honest operator compromised by coalition quorum majority
            if !op.is_sybil {
                extracted += op.reserves;
            }
            // Sybil reserves aren't real extraction (attacker stealing from self)
        } else if !is_c && hmaj && ciq > 0 {
            // Honest ledger can slash coalition members' collateral
            for &coal_member in coalition {
                if q.contains(&coal_member) {
                    slashed += net.operators[coal_member].per_lock;
                }
            }
        }
    }

    let net_profit = extracted as i64 - slashed as i64 - own_lost as i64;
    AttackResult {
        target,
        coalition: coalition.to_vec(),
        extracted,
        slashed,
        own_reserves_lost: own_lost,
        net: net_profit,
    }
}

fn combinations(items: &[usize], k: usize) -> Vec<Vec<usize>> {
    if k == 0 { return vec![vec![]]; }
    if items.len() < k { return vec![]; }
    let mut r = Vec::new();
    for mut c in combinations(&items[1..], k - 1) { c.insert(0, items[0]); r.push(c); }
    r.extend(combinations(&items[1..], k));
    r
}

/// Try all coalitions up to size max_k, return the most profitable.
fn best_attack(net: &Network, target: usize, max_k: usize) -> Option<AttackResult> {
    let op = &net.operators[target];
    let pool = &op.quorum;
    let mut best: Option<AttackResult> = None;

    for k in 2..=pool.len().min(max_k) {
        for coal in combinations(pool, k) {
            let result = simulate_attack(net, target, &coal);
            if best.as_ref().map_or(true, |b| result.net > b.net) {
                best = Some(result);
            }
        }
    }
    best
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn wallet_advice_test() {
    println!("\n=== WALLET SAFETY TEST ===\n");

    let utxo = 600_000u64; // per operator
    let q = 5;

    // Step 1: Build honest network (ring, 20 nodes, Q=5)
    let mut net = Network::ring(20, q, utxo);
    let honest_count = 20;

    // Wallet's trust anchors: 6 evenly spaced (gives mincut >= 6 for ring Q=5)
    let anchors: Vec<usize> = (0..6).map(|i| i * 20 / 6).collect();

    println!("Honest network: {} operators, Q={}, 6 anchors={:?}", honest_count, q, anchors);
    println!("  reserves={}, per_lock={}, per_lock/reserves={:.0}%\n",
        utxo / 2, utxo / (2 * q as u64),
        100.0 / q as f64);

    // Step 2: Wallet advice
    let threshold = q as u32 + 1; // mincut > Q, i.e. >= Q+1
    println!("WALLET ADVICE: require mincut >= {} to your anchors\n", threshold);

    // Check all honest nodes
    println!("--- Honest node mincuts ---");
    let n = net.operators.len();
    for i in 0..honest_count {
        if anchors.contains(&i) { continue; }
        let mc = mincut_to_anchors(n, &net.adj, i, &anchors);
        let safe = mc >= threshold;
        if !safe {
            println!("  {} mincut={} {}", net.operators[i].name, mc,
                if safe { "OK" } else { "REJECT" });
        }
    }
    let all_honest_pass = (0..honest_count)
        .filter(|i| !anchors.contains(i))
        .all(|i| mincut_to_anchors(n, &net.adj, i, &anchors) >= threshold);
    println!("  All honest nodes pass: {}\n", all_honest_pass);

    // Step 3: Try attacks on honest network (no sybils)
    println!("--- Attack: embedded coalition (no sybils) ---");
    let mut any_profitable = false;
    for target in 0..honest_count {
        if anchors.contains(&target) { continue; }
        if let Some(result) = best_attack(&net, target, 8) {
            if result.net > 0 {
                any_profitable = true;
                let coal_names: Vec<String> = result.coalition.iter()
                    .map(|&c| net.operators[c].name.clone()).collect();
                println!("  EXPLOIT: target={} coal=[{}] K={} net={:+}",
                    net.operators[target].name, coal_names.join(","),
                    result.coalition.len(), result.net);
                println!("    extracted={} slashed={} own_lost={}",
                    result.extracted, result.slashed, result.own_reserves_lost);
            }
        }
    }
    if !any_profitable {
        println!("  No profitable attack found (up to K=8)");
    }
    println!();

    // Step 4: Attach sybil island and test
    for (sybil_count, bridge_nodes) in [
        (6, vec![5, 6]),           // small island, 2 bridges
        (10, vec![3, 7, 11]),      // medium island, 3 bridges
        (16, vec![2, 5, 8, 11]),   // large island, 4 bridges
        (16, vec![1, 4, 7, 10, 13, 16]),  // large island, 6 bridges (one per anchor gap)
    ] {
        let mut net_sybil = Network::ring(20, q, utxo);
        net_sybil.attach_sybil_island(sybil_count, &bridge_nodes, q, utxo);
        let n = net_sybil.operators.len();

        println!("--- Sybil island: {} sybils, bridges={:?} ---", sybil_count, bridge_nodes);

        // Check mincut for sybil nodes
        let sybil_base = honest_count;
        let mut sybil_mincuts: Vec<(usize, u32)> = Vec::new();
        for i in sybil_base..n {
            let mc = mincut_to_anchors(n, &net_sybil.adj, i, &anchors);
            sybil_mincuts.push((i, mc));
        }
        let max_sybil_mc = sybil_mincuts.iter().map(|&(_, mc)| mc).max().unwrap_or(0);
        let sybils_accepted = sybil_mincuts.iter().filter(|&&(_, mc)| mc >= threshold).count();
        println!("  Sybil mincuts: max={}, accepted by wallet: {}/{}",
            max_sybil_mc, sybils_accepted, sybil_count);

        if sybils_accepted > 0 {
            println!("  WARNING: wallet would accept {} sybil nodes!", sybils_accepted);
        }

        // Try attacks: sybils targeting honest nodes
        let mut best_sybil_attack: Option<(String, AttackResult)> = None;
        for target in 0..honest_count {
            if anchors.contains(&target) { continue; }
            let mc = mincut_to_anchors(n, &net_sybil.adj, target, &anchors);
            if mc < threshold { continue; } // wallet would reject

            // Coalition from target's quorum (may include sybils now)
            if let Some(result) = best_attack(&net_sybil, target, 8) {
                if best_sybil_attack.as_ref().map_or(true, |b| result.net > b.1.net) {
                    best_sybil_attack = Some((net_sybil.operators[target].name.clone(), result));
                }
            }
        }

        if let Some((target_name, result)) = &best_sybil_attack {
            let coal_names: Vec<String> = result.coalition.iter()
                .map(|&c| net_sybil.operators[c].name.clone()).collect();
            let tag = if result.net > 0 { "EXPLOIT!" } else { "safe" };
            println!("  Best attack on wallet-approved honest target: {} [{}]",
                target_name, tag);
            println!("    coalition=[{}] K={}", coal_names.join(","), result.coalition.len());
            println!("    extracted={} slashed={} own_lost={} net={:+}",
                result.extracted, result.slashed, result.own_reserves_lost, result.net);
        } else {
            println!("  No attack possible on wallet-approved targets");
        }

        // Also try: sybils attacking each other (circular theft attempt)
        let mut sybil_self_steal = false;
        for &(sybil_id, mc) in &sybil_mincuts {
            // This would only matter if wallet accepted the sybil
            if mc < threshold { continue; }
            // All quorum members are sybils — attacker controls everything
            // But "stealing" from your own sybil is just moving your own money
            sybil_self_steal = true;
        }
        if sybil_self_steal && sybils_accepted > 0 {
            println!("  Note: accepted sybils have sybil-controlled quorums (self-theft only)");
        }

        println!();
    }

    // Step 5: Adversarial topology — attacker specifically tries to get mincut >= threshold
    println!("--- Adversarial bridge placement: can attacker achieve mincut >= {}? ---\n", threshold);
    println!("  Attacker needs {} independent paths to anchors.", threshold);
    println!("  Each path requires a bridge to the honest network.");
    println!("  Each bridge = real collateral posted on a real node.\n");

    // Best case: attacker places bridges on anchor-adjacent nodes
    let strategic_bridges: Vec<usize> = anchors.iter()
        .flat_map(|&a| net.adj[a].iter().copied().filter(|&x| !anchors.contains(&x)))
        .collect::<HashSet<_>>().into_iter().take(threshold as usize).collect();

    let mut net_strategic = Network::ring(20, q, utxo);
    net_strategic.attach_sybil_island(10, &strategic_bridges, q, utxo);
    let n = net_strategic.operators.len();

    println!("  Strategic bridges (anchor-adjacent): {:?}", strategic_bridges);
    let sybil_mc = mincut_to_anchors(n, &net_strategic.adj, honest_count, &anchors);
    println!("  Sybil node 0 mincut to anchors: {}", sybil_mc);
    println!("  Wallet accepts: {}\n", sybil_mc >= threshold);

    if sybil_mc >= threshold {
        // Attacker got accepted! But is theft profitable?
        // The sybil's quorum is all sybils — easy to steal deposits ON the sybil's ledger.
        // But real depositors' wallets would also check the QUORUM MEMBERS' mincuts.
        println!("  Sybil passed mincut check. But sybil's quorum members are:");
        for &m in &net_strategic.operators[honest_count].quorum {
            let mc = mincut_to_anchors(n, &net_strategic.adj, m, &anchors);
            println!("    {} mincut={} {}",
                net_strategic.operators[m].name, mc,
                if mc >= threshold { "OK" } else { "REJECT" });
        }

        println!();
        println!("  ADDITIONAL WALLET RULE: also check mincut of ALL quorum members.");
        println!("  If any quorum member fails, the quorum is compromised -> reject.");

        let quorum_pass = net_strategic.operators[honest_count].quorum.iter()
            .all(|&m| mincut_to_anchors(n, &net_strategic.adj, m, &anchors) >= threshold);
        println!("  All quorum members pass: {}", quorum_pass);
    }

    // Summary
    println!("\n=== WALLET ADVICE SUMMARY ===\n");
    println!("  1. Choose trust anchors (operators you know/trust)");
    println!("  2. For candidate operator O with quorum Q:");
    println!("     a. Compute mincut(O, your_anchors) on the quorum graph");
    println!("     b. Compute mincut(m, your_anchors) for each quorum member m");
    println!("     c. Require ALL >= {} (= Q_size + 1 for 50/50 split)", threshold);
    println!("  3. Re-check periodically (quorum memberships can change)");
    println!("  4. Threshold formula: mincut > reserves / per_lock");
    println!("     With 50/50 split: mincut > Q_size");
    println!();
    assert!(all_honest_pass, "All honest nodes should pass wallet check");
    assert!(!any_profitable, "No attack should be profitable on honest network");
}
