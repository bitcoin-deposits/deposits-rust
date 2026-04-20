//! Can we steal from wallets that enforce mincut >= 6 and clustering < 0.7?
//!
//! The wallet will only deposit on operators that pass BOTH checks.
//! "Stealing" means: attacker ends up with more than they started with.
//! Taking your own reserves back is not profit.

use std::collections::{HashSet, VecDeque};

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
    fn add_edge(&mut self, f: usize, t: usize, c: u32) {
        self.capacity[f][t] += c;
    }
    fn max_flow(&self, s: usize, t: usize) -> u32 {
        let n = self.n;
        let mut res = self.capacity.clone();
        let mut total = 0;
        loop {
            let mut par = vec![None; n];
            let mut vis = vec![false; n];
            vis[s] = true;
            let mut q = VecDeque::new();
            q.push_back(s);
            while let Some(u) = q.pop_front() {
                if u == t {
                    break;
                }
                for v in 0..n {
                    if !vis[v] && res[u][v] > 0 {
                        vis[v] = true;
                        par[v] = Some(u);
                        q.push_back(v);
                    }
                }
            }
            if !vis[t] {
                break;
            }
            let mut flow = u32::MAX;
            let mut v = t;
            while let Some(u) = par[v] {
                flow = flow.min(res[u][v]);
                v = u;
            }
            v = t;
            while let Some(u) = par[v] {
                res[u][v] -= flow;
                res[v][u] += flow;
                v = u;
            }
            total += flow;
        }
        total
    }
}

fn mincut(n: usize, adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> u32 {
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

fn clustering_coeff(adj: &[HashSet<usize>], node: usize) -> f64 {
    let neighbors: Vec<usize> = adj[node].iter().copied().collect();
    let k = neighbors.len();
    if k < 2 {
        return 0.0;
    }
    let mut connected = 0usize;
    for i in 0..k {
        for j in (i + 1)..k {
            if adj[neighbors[i]].contains(&neighbors[j]) {
                connected += 1;
            }
        }
    }
    connected as f64 / (k * (k - 1) / 2) as f64
}

// =========================================================================
// Wallet policy
// =========================================================================

const MIN_MINCUT: u32 = 6;
const MAX_CLUSTERING: f64 = 0.7;

fn wallet_accepts(n: usize, adj: &[HashSet<usize>], target: usize, anchors: &[usize]) -> bool {
    let mc = mincut(n, adj, target, anchors);
    let cc = clustering_coeff(adj, target);
    mc >= MIN_MINCUT && cc < MAX_CLUSTERING
}

// =========================================================================
// Network builder
// =========================================================================

struct Network {
    adj: Vec<HashSet<usize>>,
    is_attacker: Vec<bool>,
    reserves: Vec<u64>, // operator's own reserves on their ledger
    deposits: Vec<u64>, // wallet deposits on this operator's ledger
    quorum: Vec<Vec<usize>>,
    per_lock: Vec<u64>,
    anchors: Vec<usize>,
}

impl Network {
    /// Honest ring core with evenly spaced anchors.
    fn new(n: usize, q: usize, num_anchors: usize, utxo: u64) -> Self {
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

        Network {
            adj,
            is_attacker: vec![false; n],
            reserves: vec![reserves; n],
            deposits: vec![0; n],
            quorum,
            per_lock: vec![per_lock; n],
            anchors,
        }
    }

    fn n(&self) -> usize {
        self.adj.len()
    }

    /// Add sybil nodes. Returns the range of new node IDs.
    fn add_sybils(&mut self, count: usize, q: usize, utxo: u64) -> (usize, usize) {
        let base = self.n();
        let reserves = utxo / 2;
        let per_lock = utxo / (2 * q as u64);

        for _ in 0..count {
            self.adj.push(HashSet::new());
            self.is_attacker.push(true);
            self.reserves.push(reserves);
            self.deposits.push(0);
            self.quorum.push(Vec::new());
            self.per_lock.push(per_lock);
        }

        // Sybil internal ring quorums
        for i in 0..count {
            let id = base + i;
            let mut qm = Vec::new();
            for j in 1..=q.min(count - 1) {
                qm.push(base + ((i + j) % count));
            }
            self.quorum[id] = qm.clone();
            for &m in &qm {
                self.adj[id].insert(m);
                self.adj[m].insert(id);
            }
        }

        (base, base + count)
    }

    /// Connect sybil to honest node (bidirectional quorum edge).
    fn bridge(&mut self, sybil: usize, honest: usize) {
        self.adj[sybil].insert(honest);
        self.adj[honest].insert(sybil);
        // Sybil joins honest node's quorum
        if !self.quorum[honest].contains(&sybil) {
            self.quorum[honest].push(sybil);
        }
        // Honest joins sybil's quorum
        if !self.quorum[sybil].contains(&honest) {
            self.quorum[sybil].push(honest);
        }
    }

    /// Mark honest nodes as attacker-controlled (compromised, not sybil).
    fn compromise(&mut self, node: usize) {
        self.is_attacker[node] = true;
    }

    /// Wallet deposits on all nodes that pass the policy check.
    fn wallet_deposit(&mut self, amount: u64) -> Vec<usize> {
        let n = self.n();
        let mut deposited_on = Vec::new();
        for i in 0..n {
            if self.anchors.contains(&i) {
                continue;
            }
            if wallet_accepts(n, &self.adj, i, &self.anchors) {
                self.deposits[i] += amount;
                deposited_on.push(i);
            }
        }
        deposited_on
    }

    /// Attacker tries to steal: coalition is all attacker-controlled nodes.
    /// Returns (total_extracted_from_wallets, total_attacker_cost).
    fn attack(&self) -> AttackOutcome {
        let n = self.n();
        let coalition: Vec<usize> = (0..n).filter(|&i| self.is_attacker[i]).collect();
        let cs: HashSet<usize> = coalition.iter().copied().collect();

        let mut wallet_losses = 0u64; // wallet deposits stolen
        let mut attacker_cost = 0u64; // collateral slashed + own reserves lost

        let mut details = Vec::new();

        for i in 0..n {
            let q = &self.quorum[i];
            let ciq = q.iter().filter(|m| cs.contains(m)).count();
            let hiq = q.len() - ciq;
            let maj = q.len().div_ceil(2);
            let hmaj = hiq >= maj;
            let is_att = self.is_attacker[i];

            if is_att {
                // Attacker's own ledger
                if hmaj {
                    // Honest quorum confiscates attacker's reserves
                    attacker_cost += self.reserves[i];
                    details.push(format!(
                        "  node {:>2}: ATK own reserves {} confiscated",
                        i, self.reserves[i]
                    ));
                } else {
                    // Attacker keeps own reserves (but that's not profit)
                    details.push(format!(
                        "  node {:>2}: ATK keeps own reserves {}",
                        i, self.reserves[i]
                    ));
                }
                // Can attacker steal wallet deposits on their own ledger?
                if self.deposits[i] > 0 {
                    // Attacker IS the operator — they control the reserves output
                    // But the quorum must sign. If attacker's quorum is mostly attacker...
                    if !hmaj {
                        wallet_losses += self.deposits[i];
                        details.push(format!(
                            "  node {:>2}: ATK steals wallet deposit {}!",
                            i, self.deposits[i]
                        ));
                    } else {
                        details.push(format!(
                            "  node {:>2}: ATK cannot steal deposit {} (honest quorum)",
                            i, self.deposits[i]
                        ));
                    }
                }
            } else {
                // Honest operator's ledger
                if !hmaj {
                    // Coalition controls quorum — steal reserves AND deposits
                    wallet_losses += self.deposits[i];
                    details.push(format!(
                        "  node {:>2}: HONEST compromised, deposit {} stolen",
                        i, self.deposits[i]
                    ));
                } else if ciq > 0 {
                    // Honest quorum slashes attacker collateral
                    let slashed: u64 = coalition
                        .iter()
                        .filter(|&&c| q.contains(&c))
                        .map(|&c| self.per_lock[c])
                        .sum();
                    attacker_cost += slashed;
                    details.push(format!(
                        "  node {:>2}: HONEST safe, slashes {} from {} attacker members",
                        i,
                        slashed,
                        q.iter().filter(|m| cs.contains(m)).count()
                    ));
                }
            }
        }

        let net_theft = wallet_losses as i64 - attacker_cost as i64;

        AttackOutcome {
            wallet_losses,
            attacker_cost,
            net_theft,
            coalition_size: coalition.len(),
            details,
        }
    }
}

struct AttackOutcome {
    wallet_losses: u64,
    attacker_cost: u64,
    net_theft: i64,
    coalition_size: usize,
    details: Vec<String>,
}

fn print_outcome(label: &str, outcome: &AttackOutcome, verbose: bool) {
    let tag = if outcome.net_theft > 0 {
        "STOLEN!"
    } else {
        "FAILED"
    };
    println!(
        "  [{}] {} — K={}, wallet_loss={}, attacker_cost={}, net={:+}",
        tag,
        label,
        outcome.coalition_size,
        outcome.wallet_losses,
        outcome.attacker_cost,
        outcome.net_theft
    );
    if verbose || outcome.net_theft > 0 {
        for d in &outcome.details {
            println!("    {}", d);
        }
    }
}

// =========================================================================
// Attack strategies
// =========================================================================

#[test]
fn try_to_steal() {
    let utxo = 600_000u64;
    let q = 5;
    let deposit_amount = 100_000u64;

    println!("\n=== CAN WE STEAL FROM WALLETS? ===");
    println!(
        "  Policy: mincut >= {} AND clustering < {}",
        MIN_MINCUT, MAX_CLUSTERING
    );
    println!("  Network: 20 honest nodes, ring Q={}, 6 anchors", q);
    println!(
        "  Wallet deposits {}sat on every node that passes\n",
        deposit_amount
    );

    // =====================================================================
    // Strategy 1: Sybil island with bridges
    // =====================================================================
    println!("=== Strategy 1: Sybil island (10 sybils, 6 bridges) ===");
    {
        let mut net = Network::new(20, q, 6, utxo);
        let (sb, _se) = net.add_sybils(10, q, utxo);

        // Bridge to anchor-adjacent nodes
        net.bridge(sb, 1);
        net.bridge(sb + 1, 4);
        net.bridge(sb + 2, 7);
        net.bridge(sb + 3, 11);
        net.bridge(sb + 4, 14);
        net.bridge(sb + 5, 17);

        let deposited = net.wallet_deposit(deposit_amount);

        let sybil_accepted: Vec<usize> = (sb..sb + 10).filter(|i| deposited.contains(i)).collect();
        println!(
            "  Wallet deposited on {} nodes ({} sybils accepted)",
            deposited.len(),
            sybil_accepted.len()
        );

        let outcome = net.attack();
        print_outcome("sybil island", &outcome, true);
    }
    println!();

    // =====================================================================
    // Strategy 2: Sybil island but with sparse internal connections
    //             (trying to get clustering below 0.7)
    // =====================================================================
    println!("=== Strategy 2: Sparse sybil island (low clustering attempt) ===");
    {
        let mut net = Network::new(20, q, 6, utxo);
        // 20 sybils in a ring (not a clique) — lower clustering
        let (sb, _se) = net.add_sybils(20, q, utxo);

        // 6 bridges spread across the sybil ring
        net.bridge(sb, 1);
        net.bridge(sb + 3, 4);
        net.bridge(sb + 6, 7);
        net.bridge(sb + 10, 11);
        net.bridge(sb + 13, 14);
        net.bridge(sb + 16, 17);

        // Check what sybil clustering looks like
        let n = net.n();
        let sample_cc = clustering_coeff(&net.adj, sb + 8); // middle sybil, no bridge
        let sample_mc = mincut(n, &net.adj, sb + 8, &net.anchors);
        println!(
            "  Sybil node (no bridge) — clustering={:.3}, mincut={}",
            sample_cc, sample_mc
        );

        let bridge_cc = clustering_coeff(&net.adj, sb);
        let bridge_mc = mincut(n, &net.adj, sb, &net.anchors);
        println!(
            "  Sybil node (bridge)    — clustering={:.3}, mincut={}",
            bridge_cc, bridge_mc
        );

        let deposited = net.wallet_deposit(deposit_amount);
        let sybil_accepted: Vec<usize> = (sb..sb + 20).filter(|i| deposited.contains(i)).collect();
        println!(
            "  Wallet deposited on {} nodes ({} sybils accepted)",
            deposited.len(),
            sybil_accepted.len()
        );

        if !sybil_accepted.is_empty() {
            let outcome = net.attack();
            print_outcome("sparse sybil island", &outcome, true);
        } else {
            println!("  No sybils accepted — attack impossible");
        }
    }
    println!();

    // =====================================================================
    // Strategy 3: Compromise real nodes instead of creating sybils
    // =====================================================================
    println!("=== Strategy 3: Compromise real nodes (bribe/hack) ===");
    for num_compromised in [2, 3, 4, 5, 6, 8] {
        let mut net = Network::new(20, q, 6, utxo);
        // Compromise adjacent nodes (worst case for ring)
        for i in 0..num_compromised {
            net.compromise(1 + i); // nodes 1,2,3,... (not anchors)
        }

        let deposited = net.wallet_deposit(deposit_amount);
        let outcome = net.attack();
        print_outcome(
            &format!("{} compromised adjacent", num_compromised),
            &outcome,
            outcome.net_theft > 0,
        );
    }
    println!();

    // =====================================================================
    // Strategy 4: Compromise non-adjacent nodes (spread across ring)
    // =====================================================================
    println!("=== Strategy 4: Compromise spread-out nodes ===");
    for num_compromised in [2, 3, 4, 6] {
        let mut net = Network::new(20, q, 6, utxo);
        // Evenly spaced compromised nodes
        for i in 0..num_compromised {
            let node = 1 + i * 20 / num_compromised;
            if !net.anchors.contains(&node) {
                net.compromise(node);
            }
        }

        let deposited = net.wallet_deposit(deposit_amount);
        let outcome = net.attack();
        print_outcome(
            &format!("{} compromised spread", num_compromised),
            &outcome,
            outcome.net_theft > 0,
        );
    }
    println!();

    // =====================================================================
    // Strategy 5: Mixed — sybils + compromise bridge nodes
    // =====================================================================
    println!("=== Strategy 5: Sybils + compromise their bridge nodes ===");
    {
        let mut net = Network::new(20, q, 6, utxo);
        let (sb, _) = net.add_sybils(10, q, utxo);

        // Bridges
        let bridge_honest = vec![1, 4, 7, 11, 14, 17];
        for (i, &h) in bridge_honest.iter().enumerate() {
            net.bridge(sb + i, h);
        }

        // Also compromise the bridge nodes themselves
        for &h in &bridge_honest {
            net.compromise(h);
        }

        let deposited = net.wallet_deposit(deposit_amount);
        let n = net.n();

        // Show bridge node status
        for &h in &bridge_honest {
            let mc = mincut(n, &net.adj, h, &net.anchors);
            let cc = clustering_coeff(&net.adj, h);
            let accepted = deposited.contains(&h);
            println!(
                "  Compromised bridge {} — mc={}, cc={:.3}, accepted={}",
                h, mc, cc, accepted
            );
        }

        let outcome = net.attack();
        print_outcome("sybils + compromised bridges", &outcome, true);
    }
    println!();

    // =====================================================================
    // Strategy 6: Attacker slowly infiltrates — becomes legit then turns
    // =====================================================================
    println!("=== Strategy 6: Legitimate operator turns malicious ===");
    {
        // One honest operator (node 2) decides to steal
        let mut net = Network::new(20, q, 6, utxo);
        let deposited = net.wallet_deposit(deposit_amount);

        println!("  Wallet deposited on {} nodes", deposited.len());
        println!("  Node 2 turns malicious...");

        net.compromise(2);
        let outcome = net.attack();
        print_outcome("single rogue operator", &outcome, true);
    }
    println!();

    // =====================================================================
    // Strategy 7: Attacker IS an anchor (worst case trust failure)
    // =====================================================================
    println!("=== Strategy 7: Compromised anchor ===");
    {
        let mut net = Network::new(20, q, 6, utxo);
        let deposited = net.wallet_deposit(deposit_amount);

        // Anchor 0 turns malicious along with its neighbors
        net.compromise(0);
        net.compromise(1);
        net.compromise(19);

        let outcome = net.attack();
        print_outcome("compromised anchor + 2 neighbors", &outcome, true);
    }
}
