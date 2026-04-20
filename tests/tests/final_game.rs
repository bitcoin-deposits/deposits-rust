//! The final game: attacker vs defender, wallets fund what passes.
//!
//! Setup:
//!   - 100 node positions in a network
//!   - Defender fills 51 as honest, attacker fills 49
//!   - Both choose their own quorum members freely
//!   - Attacker sees defender's topology before choosing (worst case)
//!   - Wallet sees the full graph, applies a metric, funds all that pass
//!   - Attacker tries to profit from those funded nodes
//!
//! The attacker wins if net profit > 0 (wallet deposits stolen > collateral lost).

use std::collections::{HashSet, VecDeque};

const N: usize = 100;
const Q: usize = 5;
const UTXO: u64 = 600_000;
const DEPOSIT: u64 = 100_000;

// =========================================================================
// Flow graph for quorum-mincut
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

fn quorum_mincut(adj: &[HashSet<usize>], quorum: &[usize], anchors: &[usize]) -> u32 {
    let n = adj.len();
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
// Game state
// =========================================================================

struct Game {
    quorums: Vec<Vec<usize>>,
    adj: Vec<HashSet<usize>>,
    is_attacker: Vec<bool>,
    anchors: Vec<usize>,
}

impl Game {
    fn new() -> Self {
        Game {
            quorums: vec![Vec::new(); N],
            adj: vec![HashSet::new(); N],
            is_attacker: vec![false; N],
            anchors: vec![0, 16, 33, 50, 66, 83],
        }
    }

    fn set_quorum(&mut self, node: usize, members: Vec<usize>) {
        for &m in &members {
            self.adj[node].insert(m);
            self.adj[m].insert(node);
        }
        self.quorums[node] = members;
    }

    /// Wallet applies metric, deposits on all passing non-anchor nodes.
    /// Returns (deposits_vec, count_funded_honest, count_funded_attacker)
    fn wallet_fund(&self, qmc_threshold: u32) -> (Vec<u64>, usize, usize) {
        let mut deposits = vec![0u64; N];
        let mut funded_h = 0;
        let mut funded_a = 0;
        for i in 0..N {
            if self.anchors.contains(&i) {
                continue;
            }
            if self.quorums[i].is_empty() {
                continue;
            }
            let qmc = quorum_mincut(&self.adj, &self.quorums[i], &self.anchors);
            if qmc >= qmc_threshold {
                deposits[i] = DEPOSIT;
                if self.is_attacker[i] {
                    funded_a += 1;
                } else {
                    funded_h += 1;
                }
            }
        }
        (deposits, funded_h, funded_a)
    }

    /// Attacker defects. Returns (wallet_loss, attacker_cost, net).
    fn attack(&self, deposits: &[u64]) -> (u64, u64, i64) {
        let per_lock = UTXO / (2 * Q as u64);
        let attackers: HashSet<usize> = (0..N).filter(|&i| self.is_attacker[i]).collect();
        let mut wloss = 0u64;
        let mut acost = 0u64;
        for i in 0..N {
            let q = &self.quorums[i];
            if q.is_empty() {
                continue;
            }
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
                    acost += q.iter().filter(|m| attackers.contains(m)).count() as u64 * per_lock;
                }
            }
        }
        (wloss, acost, wloss as i64 - acost as i64)
    }
}

fn print_result(label: &str, funded_h: usize, funded_a: usize, wloss: u64, acost: u64, net: i64) {
    let tag = if net > 0 { "STOLEN!" } else { "SAFE" };
    println!(
        "  [{:>6}] {:>40} | funded h={:>2} a={:>2} | wloss={:>8} acost={:>8} net={:>+9}",
        tag, label, funded_h, funded_a, wloss, acost, net
    );
}

// =========================================================================
// The game
// =========================================================================

#[test]
fn the_final_game() {
    println!("\n=== THE FINAL GAME: 51 honest vs 49 attacker ===");
    println!("  Attacker sees defender topology, optimizes placement.");
    println!("  Wallet funds all nodes passing quorum-mincut >= threshold.\n");

    // Defender: 51 honest nodes (0-50), dispersed quorums among all 100
    // The defender doesn't know who's attacker, so picks from all N
    let honest: Vec<usize> = (0..51).collect();
    let attacker: Vec<usize> = (51..100).collect();
    let anchors = [0, 16, 33, 50, 66, 83]; // within honest range

    // Sweep quorum-mincut thresholds
    for qmc_thresh in [0, 5, 10, 20, 50] {
        println!("=== Quorum-mincut threshold: {} ===\n", qmc_thresh);

        // -----------------------------------------------------------------
        // Attacker strategy A: All-attacker quorums (internal sybil ring)
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            // Defender: dispersed quorums from the full network
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            // Attacker: ring among themselves
            for (idx, &i) in attacker.iter().enumerate() {
                g.is_attacker[i] = true;
                let members: Vec<usize> = (1..=Q).map(|j| attacker[(idx + j) % 49]).collect();
                g.set_quorum(i, members);
            }
            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("A: attacker sybil ring", fh, fa, wl, ac, net);
        }

        // -----------------------------------------------------------------
        // Attacker strategy B: Include honest in attacker quorums
        //                      (2 attacker + 3 honest per quorum)
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            for (idx, &i) in attacker.iter().enumerate() {
                g.is_attacker[i] = true;
                let a1 = attacker[(idx + 1) % 49];
                let a2 = attacker[(idx + 2) % 49];
                let h1 = honest[(idx * 3) % 51];
                let h2 = honest[(idx * 3 + 10) % 51];
                let h3 = honest[(idx * 3 + 25) % 51];
                g.set_quorum(i, vec![a1, a2, h1, h2, h3]);
            }
            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("B: 2atk+3honest quorum", fh, fa, wl, ac, net);
        }

        // -----------------------------------------------------------------
        // Attacker strategy C: 3 attacker + 2 honest (attacker majority)
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            for (idx, &i) in attacker.iter().enumerate() {
                g.is_attacker[i] = true;
                let a1 = attacker[(idx + 1) % 49];
                let a2 = attacker[(idx + 2) % 49];
                let a3 = attacker[(idx + 3) % 49];
                let h1 = honest[(idx * 2) % 51];
                let h2 = honest[(idx * 2 + 25) % 51];
                g.set_quorum(i, vec![a1, a2, a3, h1, h2]);
            }
            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("C: 3atk+2honest (atk majority)", fh, fa, wl, ac, net);
        }

        // -----------------------------------------------------------------
        // Attacker strategy D: mimic defender topology exactly
        //                      (dispersed quorum from full network)
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            for &i in &attacker {
                g.is_attacker[i] = true;
                // Same dispersed strategy as defender
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("D: mimic defender (dispersed)", fh, fa, wl, ac, net);
        }

        // -----------------------------------------------------------------
        // Attacker strategy E: cluster attack — all 49 adjacent, ring quorum
        //                      among themselves, bridges to honest
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            for (idx, &i) in attacker.iter().enumerate() {
                g.is_attacker[i] = true;
                // Ring quorum with bridges
                let mut members: Vec<usize> = Vec::new();
                // 4 attacker neighbors
                for j in 1..=4 {
                    members.push(attacker[(idx + j) % 49]);
                }
                // 1 honest bridge
                members.push(honest[idx % 51]);
                members.truncate(Q);
                g.set_quorum(i, members);
            }
            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("E: atk ring + 1 honest bridge", fh, fa, wl, ac, net);
        }

        // -----------------------------------------------------------------
        // Attacker strategy F: target honest quorums
        // Honest nodes have dispersed quorums from full N, so ~49% of their
        // quorum members will be attacker nodes. Check if this lets attacker
        // steal from honest nodes.
        // -----------------------------------------------------------------
        {
            let mut g = Game::new();
            for &i in &honest {
                let stride = N / (Q + 1);
                let members: Vec<usize> = (1..=Q).map(|j| (i + j * stride) % N).collect();
                g.set_quorum(i, members);
            }
            // Attacker doesn't even make quorums — just sits on honest quorums
            for &i in &attacker {
                g.is_attacker[i] = true;
            }

            // How many honest quorums have attacker majority?
            let mut att_majority = 0;
            let mut att_count_dist: Vec<usize> = vec![0; Q + 1];
            for &i in &honest {
                let atk_in_q = g.quorums[i].iter().filter(|&&m| g.is_attacker[m]).count();
                att_count_dist[atk_in_q] += 1;
                if atk_in_q >= Q.div_ceil(2) {
                    att_majority += 1;
                }
            }

            let (deps, fh, fa) = g.wallet_fund(qmc_thresh);
            let (wl, ac, net) = g.attack(&deps);
            print_result("F: sit on honest quorums", fh, fa, wl, ac, net);
            println!("      Honest quorum attacker counts: {:?}", att_count_dist);
            println!(
                "      Honest quorums with attacker majority: {}/{}",
                att_majority,
                honest.len()
            );
        }

        println!();
    }
}
