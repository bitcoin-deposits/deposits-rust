//! Turn-based placement game.
//!
//! Nodes arrive in waves. Each node forms a quorum by inviting existing nodes.
//! Existing nodes can REFUSE to join based on graph metrics.
//! Wallets fund nodes that pass acceptance criteria.
//! Attacker tries to profit.

use std::collections::HashSet;

const Q: usize = 5;
const UTXO: u64 = 600_000;
const DEPOSIT: u64 = 100_000;

struct Network {
    quorums: Vec<Vec<usize>>, // who watches this node's ledger
    is_attacker: Vec<bool>,
    anchors: HashSet<usize>,
}

impl Network {
    fn new() -> Self {
        Network {
            quorums: Vec::new(),
            is_attacker: Vec::new(),
            anchors: HashSet::new(),
        }
    }

    fn n(&self) -> usize {
        self.quorums.len()
    }

    fn add_node(&mut self, is_attacker: bool) -> usize {
        let id = self.n();
        self.quorums.push(Vec::new());
        self.is_attacker.push(is_attacker);
        id
    }

    /// Node `inviter` asks `target` to join its quorum.
    /// Target decides based on acceptance rule.
    fn invite(&mut self, inviter: usize, target: usize, accept: bool) -> bool {
        if !accept {
            return false;
        }
        if self.quorums[inviter].contains(&target) {
            return false;
        }
        if self.quorums[inviter].len() >= Q {
            return false;
        }
        self.quorums[inviter].push(target);
        true
    }

    /// How many anchors/trusted nodes are in this node's quorum?
    fn anchor_count_in_quorum(&self, node: usize) -> usize {
        self.quorums[node]
            .iter()
            .filter(|m| self.anchors.contains(m))
            .count()
    }

    /// How many of this node's quorum members have anchors in THEIR quorum?
    fn quorum_trust_depth(&self, node: usize) -> usize {
        self.quorums[node]
            .iter()
            .filter(|&&m| self.anchor_count_in_quorum(m) > 0 || self.anchors.contains(&m))
            .count()
    }

    fn attack(&self, deposits: &[u64]) -> (u64, u64, i64) {
        let per_lock = UTXO / (2 * Q as u64);
        let attackers: HashSet<usize> = (0..self.n()).filter(|&i| self.is_attacker[i]).collect();
        let mut wloss = 0u64;
        let mut acost = 0u64;
        for i in 0..self.n() {
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
                    acost += ciq as u64 * per_lock;
                }
            }
        }
        (wloss, acost, wloss as i64 - acost as i64)
    }
}

#[test]
fn turn_based_game() {
    println!("\n=== TURN-BASED PLACEMENT GAME ===\n");
    println!("  Honest node acceptance rule: only join quorum of a node that");
    println!("  already has >= 1 anchor in its quorum (or IS an anchor).");
    println!("  This means: you need anchor endorsement to grow.\n");

    let mut net = Network::new();

    // =================================================================
    // WAVE 1: Defender places 8 founding nodes (including 6 anchors)
    // =================================================================
    println!("--- Wave 1: Defender places 8 honest founders ---");
    let mut honest_nodes: Vec<usize> = Vec::new();
    for i in 0..8 {
        let id = net.add_node(false);
        honest_nodes.push(id);
        if i < 6 {
            net.anchors.insert(id);
        }
    }

    // Founders form quorums among themselves
    for &i in &honest_nodes {
        for j in 1..=Q {
            let m = honest_nodes[(i + j) % 8];
            net.invite(i, m, true);
        }
    }

    // Verify founders
    for &i in &honest_nodes {
        let ac = net.anchor_count_in_quorum(i);
        println!(
            "  node {} ({}): quorum={:?}, anchors_in_quorum={}",
            i,
            if net.anchors.contains(&i) {
                "anchor"
            } else {
                "honest"
            },
            net.quorums[i],
            ac
        );
    }
    println!();

    // =================================================================
    // WAVE 2: Attacker places 20 nodes
    // =================================================================
    println!("--- Wave 2: Attacker places 20 nodes ---");
    let mut attacker_nodes: Vec<usize> = Vec::new();
    for _ in 0..20 {
        let id = net.add_node(true);
        attacker_nodes.push(id);
    }

    // Attacker tries to form quorums. They invite honest nodes.
    // Honest node acceptance rule: only join if inviter already has >= 1 anchor
    let mut att_accepted = 0;
    for &a in &attacker_nodes {
        // Try to invite honest nodes
        for &h in &honest_nodes {
            if net.quorums[a].len() >= Q {
                break;
            }
            let inviter_has_anchor = net.anchor_count_in_quorum(a) >= 1;
            // Honest node checks: does inviter already have anchor endorsement?
            let accept = inviter_has_anchor;
            net.invite(a, h, accept);
        }
        // Fill rest with other attackers
        for &a2 in &attacker_nodes {
            if net.quorums[a].len() >= Q {
                break;
            }
            if a2 != a {
                net.invite(a, a2, true);
            }
        }
        if net.quorums[a].len() == Q {
            att_accepted += 1;
        }
    }
    println!(
        "  Attackers with full quorums: {}/{}",
        att_accepted,
        attacker_nodes.len()
    );

    // Check: how many honest nodes ended up in attacker quorums?
    let honest_in_att_quorums: usize = attacker_nodes
        .iter()
        .flat_map(|&a| net.quorums[a].iter())
        .filter(|&&m| !net.is_attacker[m])
        .collect::<HashSet<_>>()
        .len();
    println!(
        "  Honest nodes in attacker quorums: {}",
        honest_in_att_quorums
    );

    // Attacker also tries to get into honest quorums by being invited
    // But honest nodes won't invite attackers — they don't know who's attacker.
    // However, honest nodes in wave 3 might invite ANYONE with good metrics.
    println!();

    // =================================================================
    // WAVE 3: Defender places 20 more honest nodes
    // =================================================================
    println!("--- Wave 3: Defender places 20 honest nodes ---");
    let mut wave3_honest: Vec<usize> = Vec::new();
    for _ in 0..20 {
        let id = net.add_node(false);
        honest_nodes.push(id);
        wave3_honest.push(id);
    }

    // These honest nodes form quorums. They pick from ALL existing nodes.
    // Acceptance rule when inviting: prefer nodes with anchor connections.
    // But they don't know who's attacker.
    // Rule: invite nodes that have >= 1 anchor in their own quorum.
    for &h in &wave3_honest {
        let candidates: Vec<usize> = (0..net.n())
            .filter(|&c| c != h && !net.quorums[h].contains(&c))
            .filter(|&c| {
                // Only invite nodes that have anchor endorsement
                net.anchor_count_in_quorum(c) >= 1 || net.anchors.contains(&c)
            })
            .collect();

        // Pick Q from candidates, dispersed
        let stride = if candidates.len() > Q {
            candidates.len() / Q
        } else {
            1
        };
        for j in 0..Q.min(candidates.len()) {
            let m = candidates[(j * stride) % candidates.len()];
            net.invite(h, m, true);
        }
    }

    let wave3_quorum_info: Vec<(usize, usize, usize)> = wave3_honest
        .iter()
        .map(|&h| {
            let ac = net.anchor_count_in_quorum(h);
            let att_in_q = net.quorums[h]
                .iter()
                .filter(|&&m| net.is_attacker[m])
                .count();
            (h, ac, att_in_q)
        })
        .collect();

    let w3_with_att_majority = wave3_quorum_info
        .iter()
        .filter(|&&(_, _, att)| att >= Q.div_ceil(2))
        .count();
    println!(
        "  Wave 3 nodes with attacker majority in quorum: {}/{}",
        w3_with_att_majority,
        wave3_honest.len()
    );
    println!(
        "  Wave 3 anchors in quorum: min={}, max={}",
        wave3_quorum_info.iter().map(|x| x.1).min().unwrap_or(0),
        wave3_quorum_info.iter().map(|x| x.1).max().unwrap_or(0)
    );
    println!();

    // =================================================================
    // WAVE 4: Attacker places 29 more nodes (total 49)
    // =================================================================
    println!("--- Wave 4: Attacker places 29 more nodes (total 49) ---");
    for _ in 0..29 {
        let id = net.add_node(true);
        attacker_nodes.push(id);
    }

    // Attacker forms quorums — same strategy
    for &a in &attacker_nodes[20..] {
        for &h in &honest_nodes {
            if net.quorums[a].len() >= Q {
                break;
            }
            let inviter_has_anchor = net.anchor_count_in_quorum(a) >= 1;
            net.invite(a, h, inviter_has_anchor);
        }
        for &a2 in &attacker_nodes {
            if net.quorums[a].len() >= Q {
                break;
            }
            if a2 != a {
                net.invite(a, a2, true);
            }
        }
    }
    println!();

    // =================================================================
    // WAVE 5: Defender places 23 more honest nodes (total 51)
    // =================================================================
    println!("--- Wave 5: Defender places 23 more honest nodes (total 51) ---");
    let mut wave5_honest: Vec<usize> = Vec::new();
    for _ in 0..23 {
        let id = net.add_node(false);
        honest_nodes.push(id);
        wave5_honest.push(id);
    }

    for &h in &wave5_honest {
        let candidates: Vec<usize> = (0..net.n())
            .filter(|&c| c != h && !net.quorums[h].contains(&c))
            .filter(|&c| net.anchor_count_in_quorum(c) >= 1 || net.anchors.contains(&c))
            .collect();
        let stride = if candidates.len() > Q {
            candidates.len() / Q
        } else {
            1
        };
        for j in 0..Q.min(candidates.len()) {
            let m = candidates[(j * stride) % candidates.len()];
            net.invite(h, m, true);
        }
    }
    println!();

    // =================================================================
    // FINAL STATE
    // =================================================================
    let n = net.n();
    let total_honest = honest_nodes.len();
    let total_attacker = attacker_nodes.len();
    println!(
        "=== FINAL STATE: {} nodes ({} honest, {} attacker) ===\n",
        n, total_honest, total_attacker
    );

    // Check honest quorums
    let mut h_att_majority = 0;
    let mut h_att_counts = vec![0usize; Q + 1];
    for &h in &honest_nodes {
        let att_in_q = net.quorums[h]
            .iter()
            .filter(|&&m| net.is_attacker[m])
            .count();
        if att_in_q <= Q {
            h_att_counts[att_in_q] += 1;
        }
        if att_in_q >= Q.div_ceil(2) {
            h_att_majority += 1;
        }
    }
    println!("  Honest quorum attacker counts: {:?}", h_att_counts);
    println!(
        "  Honest quorums with attacker majority: {}/{}",
        h_att_majority, total_honest
    );

    // Check attacker quorums
    let mut a_honest_majority = 0;
    for &a in &attacker_nodes {
        let hon_in_q = net.quorums[a]
            .iter()
            .filter(|&&m| !net.is_attacker[m])
            .count();
        if hon_in_q >= Q.div_ceil(2) {
            a_honest_majority += 1;
        }
    }
    println!(
        "  Attacker quorums with honest majority: {}/{}",
        a_honest_majority, total_attacker
    );
    println!();

    // =================================================================
    // WALLET DEPOSITS
    // =================================================================
    // Wallet rule: deposit on nodes whose quorum has >= 2 anchors
    println!("=== WALLET: deposit on nodes with >= 2 anchors in quorum ===\n");
    let mut deposits = vec![0u64; n];
    let mut funded_h = 0;
    let mut funded_a = 0;
    for i in 0..n {
        if net.anchors.contains(&i) {
            continue;
        }
        if net.quorums[i].len() < Q {
            continue;
        }
        if net.anchor_count_in_quorum(i) >= 2 {
            deposits[i] = DEPOSIT;
            if net.is_attacker[i] {
                funded_a += 1;
            } else {
                funded_h += 1;
            }
        }
    }
    println!("  Funded: {} honest, {} attacker", funded_h, funded_a);

    let (wl, ac, net_profit) = net.attack(&deposits);
    let tag = if net_profit > 0 { "STOLEN!" } else { "SAFE" };
    println!(
        "  [{}] wallet_loss={}, attacker_cost={}, net={:+}\n",
        tag, wl, ac, net_profit
    );

    // Also try: wallet rule = anchor in quorum + quorum trust depth
    println!("=== WALLET: deposit on nodes where majority of quorum is anchor-connected ===\n");
    let mut deposits2 = vec![0u64; n];
    let mut funded_h2 = 0;
    let mut funded_a2 = 0;
    for i in 0..n {
        if net.anchors.contains(&i) {
            continue;
        }
        if net.quorums[i].len() < Q {
            continue;
        }
        let trust_depth = net.quorum_trust_depth(i);
        if trust_depth >= Q.div_ceil(2) {
            // majority of quorum is anchor-connected
            deposits2[i] = DEPOSIT;
            if net.is_attacker[i] {
                funded_a2 += 1;
            } else {
                funded_h2 += 1;
            }
        }
    }
    println!("  Funded: {} honest, {} attacker", funded_h2, funded_a2);

    let (wl2, ac2, net2) = net.attack(&deposits2);
    let tag2 = if net2 > 0 { "STOLEN!" } else { "SAFE" };
    println!(
        "  [{}] wallet_loss={}, attacker_cost={}, net={:+}\n",
        tag2, wl2, ac2, net2
    );

    // Wallet rule: deposit everywhere, no filter
    println!("=== WALLET: deposit everywhere (no filter) ===\n");
    let mut deposits3 = vec![0u64; n];
    for i in 0..n {
        if net.anchors.contains(&i) {
            continue;
        }
        if net.quorums[i].len() >= Q {
            deposits3[i] = DEPOSIT;
        }
    }
    let (wl3, ac3, net3) = net.attack(&deposits3);
    let tag3 = if net3 > 0 { "STOLEN!" } else { "SAFE" };
    println!(
        "  [{}] wallet_loss={}, attacker_cost={}, net={:+}\n",
        tag3, wl3, ac3, net3
    );

    // Breakdown: where did losses come from?
    if wl3 > 0 {
        let attackers: HashSet<usize> = attacker_nodes.iter().copied().collect();
        let stolen_from_honest: u64 = honest_nodes
            .iter()
            .filter(|&&h| {
                let ciq = net.quorums[h]
                    .iter()
                    .filter(|m| attackers.contains(m))
                    .count();
                ciq >= net.quorums[h].len().div_ceil(2)
            })
            .map(|&h| deposits3[h])
            .sum();
        let stolen_from_attacker: u64 = attacker_nodes
            .iter()
            .filter(|&&a| {
                deposits3[a] > 0 && {
                    let ciq = net.quorums[a]
                        .iter()
                        .filter(|m| attackers.contains(m))
                        .count();
                    ciq >= net.quorums[a].len().div_ceil(2)
                }
            })
            .map(|&a| deposits3[a])
            .sum();
        println!(
            "  Breakdown: from honest nodes={}, from attacker nodes={}",
            stolen_from_honest, stolen_from_attacker
        );
    }
}
