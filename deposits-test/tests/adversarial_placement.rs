//! Attacker vs Defender: adversarial node placement.
//!
//! Defender places 51 honest nodes with optimal topology.
//! Attacker places 49 nodes with optimal topology.
//! Both know each other's strategy. Wallet uses best available metric.
//! Can the attacker profit?

use std::collections::HashSet;

const N_HONEST: usize = 51;
const N_ATTACK: usize = 49;
const N: usize = N_HONEST + N_ATTACK;
const Q: usize = 5;
const UTXO: u64 = 600_000;
const DEPOSIT: u64 = 100_000;

fn anchors() -> Vec<usize> {
    vec![0, 8, 17, 25, 34, 42]
} // within honest range

// =========================================================================
// Attack economics
// =========================================================================

fn attack(quorums: &[Vec<usize>], attackers: &HashSet<usize>, deposits: &[u64]) -> (i64, u64, u64) {
    let per_lock = UTXO / (2 * Q as u64);
    let mut wloss = 0u64;
    let mut acost = 0u64;
    for i in 0..quorums.len() {
        let q = &quorums[i];
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
    (wloss as i64 - acost as i64, wloss, acost)
}

fn min_majority_arc(quorum: &[usize], n: usize) -> usize {
    if quorum.is_empty() {
        return 0;
    }
    let majority = quorum.len().div_ceil(2);
    let mut positions: Vec<usize> = quorum.to_vec();
    positions.sort();
    let mut min_arc = n;
    for i in 0..positions.len() {
        let end = (i + majority - 1) % positions.len();
        let arc = if end >= i {
            positions[end] - positions[i]
        } else {
            (n - positions[i]) + positions[end]
        };
        if arc < min_arc {
            min_arc = arc;
        }
    }
    min_arc
}

#[test]
fn adversarial_placement() {
    let anch = anchors();
    let anchor_set: HashSet<usize> = anch.iter().copied().collect();

    println!("\n=== ADVERSARIAL PLACEMENT: 51 honest vs 49 attacker ===");
    println!("  N={}, Q={}, 6 trusted anchors in honest set", N, Q);
    println!("  Defender places honest nodes 0-50 (including anchors)");
    println!("  Attacker places nodes 51-99");
    println!("  Both choose their own quorum members freely\n");

    // =================================================================
    // DEFENDER STRATEGY: dispersed quorums among honest nodes only
    // Each honest node picks Q members spread across honest range
    // =================================================================
    let mut quorums: Vec<Vec<usize>> = vec![Vec::new(); N];
    let honest: Vec<usize> = (0..N_HONEST).collect();

    for &i in &honest {
        let stride = N_HONEST / (Q + 1);
        let mut members: Vec<usize> = Vec::new();
        for j in 1..=Q {
            let idx = (i + j * stride) % N_HONEST;
            if idx != i && !members.contains(&idx) {
                members.push(idx);
            }
        }
        while members.len() < Q {
            let m = (i + members.len() + 1) % N_HONEST;
            if m != i && !members.contains(&m) {
                members.push(m);
            }
        }
        quorums[i] = members;
    }

    // Wallet metric: MinArc among honest-node IDs, require >= N_HONEST/Q
    let min_arc_threshold = N_HONEST / Q; // 10

    println!("--- Defender: dispersed quorums among honest nodes ---");
    println!(
        "  Wallet rule: MinArc >= {} (among honest node IDs)\n",
        min_arc_threshold
    );

    // Verify all honest nodes pass
    let honest_pass = honest
        .iter()
        .filter(|&&i| !anchor_set.contains(&i))
        .all(|&i| min_majority_arc(&quorums[i], N_HONEST) >= min_arc_threshold);
    println!("  All honest nodes pass wallet check: {}\n", honest_pass);

    // Wallet deposits on honest nodes only (attacker nodes haven't been placed yet)
    let mut deposits = vec![0u64; N];
    for &i in &honest {
        if !anchor_set.contains(&i) {
            deposits[i] = DEPOSIT;
        }
    }
    let total_deposited: u64 = deposits.iter().sum();
    println!(
        "  Wallet deposits: {} on {} honest nodes\n",
        total_deposited,
        honest.iter().filter(|&&i| deposits[i] > 0).count()
    );

    // =================================================================
    // ATTACKER STRATEGIES
    // =================================================================

    let attacker_nodes: Vec<usize> = (N_HONEST..N).collect();
    let attacker_set: HashSet<usize> = attacker_nodes.iter().copied().collect();

    // --- Strategy 1: Attacker forms isolated island (no connections to honest) ---
    println!("=== Attacker Strategy 1: Isolated island ===");
    {
        let mut q = quorums.clone();
        // Sybil quorums among themselves
        for i in 0..N_ATTACK {
            let id = N_HONEST + i;
            q[id] = (1..=Q).map(|j| N_HONEST + ((i + j) % N_ATTACK)).collect();
        }
        let (net, wloss, acost) = attack(&q, &attacker_set, &deposits);
        println!("  No connection to honest network.");
        println!(
            "  wallet_loss={}, attacker_cost={}, net={:+}",
            wloss, acost, net
        );
        println!("  (Attacker can't reach honest quorums — zero impact)\n");
    }

    // --- Strategy 2: Attacker joins honest nodes' quorums ---
    // Attacker nodes try to get added to honest quorums.
    // But defender chose quorums — attacker can't change them!
    println!("=== Attacker Strategy 2: Try to join honest quorums ===");
    {
        println!("  Defender already fixed honest quorums. Attacker can't modify them.");
        println!("  Attacker can only choose their OWN quorum members.\n");
    }

    // --- Strategy 3: Attacker includes honest nodes in their own quorums ---
    // Then tries to get wallets to deposit on attacker nodes
    println!("=== Attacker Strategy 3: Include honest in attacker quorums, lure wallets ===");
    {
        let mut q = quorums.clone();
        // Each attacker: 2 sybils + 3 honest (to look legitimate)
        for i in 0..N_ATTACK {
            let id = N_HONEST + i;
            let s1 = N_HONEST + ((i + 1) % N_ATTACK);
            let s2 = N_HONEST + ((i + 2) % N_ATTACK);
            let h1 = (i * 3) % N_HONEST;
            let h2 = (i * 3 + 1) % N_HONEST;
            let h3 = (i * 3 + 10) % N_HONEST;
            q[id] = vec![s1, s2, h1, h2, h3];
        }

        // Wallet checks attacker nodes: do they pass MinArc?
        let mut att_deposits = deposits.clone();
        let mut att_accepted = 0;
        for &id in &attacker_nodes {
            // Wallet computes MinArc on the quorum
            let arc = min_majority_arc(&q[id], N);
            if arc >= min_arc_threshold {
                att_deposits[id] = DEPOSIT;
                att_accepted += 1;
            }
        }
        println!("  Attacker nodes with honest quorum members:");
        println!(
            "  MinArc threshold: {}, accepted: {}/{}",
            min_arc_threshold, att_accepted, N_ATTACK
        );

        if att_accepted > 0 {
            let (net, wloss, acost) = attack(&q, &attacker_set, &att_deposits);
            println!(
                "  wallet_loss={}, attacker_cost={}, net={:+}",
                wloss, acost, net
            );

            // But honest majority in quorum blocks theft!
            let att_blocked = attacker_nodes
                .iter()
                .filter(|&&id| {
                    let ciq = q[id].iter().filter(|m| attacker_set.contains(m)).count();
                    let hiq = q[id].len() - ciq;
                    hiq >= q[id].len().div_ceil(2)
                })
                .count();
            println!(
                "  Attacker nodes where honest quorum blocks theft: {}/{}",
                att_blocked, att_accepted
            );
        } else {
            println!("  No attacker nodes accepted by wallet.");
        }
        println!();
    }

    // --- Strategy 4: Attacker quorums are ALL sybil, but bridge to honest ---
    // to try to pump some metric
    println!("=== Attacker Strategy 4: All-sybil quorums with bridges ===");
    {
        let mut q = quorums.clone();
        for i in 0..N_ATTACK {
            let id = N_HONEST + i;
            q[id] = (1..=Q).map(|j| N_HONEST + ((i + j) % N_ATTACK)).collect();
        }
        // Bridges: some attackers add honest nodes as extra quorum members
        // (doesn't change their own quorum — just creates graph edges)
        // Actually attacker adds honest to their quorum to create edges
        for i in 0..6 {
            let atk = N_HONEST + i * 8;
            if atk < N {
                q[atk].push(i * 8); // bridge to honest
            }
        }

        let mut att_deposits = deposits.clone();
        let mut att_accepted = 0;
        for &id in &attacker_nodes {
            let arc = min_majority_arc(&q[id], N);
            if arc >= min_arc_threshold {
                att_deposits[id] = DEPOSIT;
                att_accepted += 1;
            }
        }
        println!("  All-sybil quorums, 6 bridges to honest network");
        println!(
            "  MinArc threshold: {}, accepted: {}/{}",
            min_arc_threshold, att_accepted, N_ATTACK
        );

        if att_accepted > 0 {
            // Check: even if wallet accepts, can attacker steal?
            let (net, wloss, acost) = attack(&q, &attacker_set, &att_deposits);
            println!(
                "  wallet_loss={}, attacker_cost={}, net={:+}",
                wloss, acost, net
            );
        } else {
            println!("  All-sybil quorums have low MinArc among their members — rejected.");
        }
        println!();
    }

    // --- Strategy 5: Attacker compromises some honest nodes ---
    // They bribe/hack N honest nodes and take over their quorum positions
    println!("=== Attacker Strategy 5: Compromise K honest nodes ===");
    for compromised_count in [5, 10, 15, 20, 25] {
        let mut attackers_total = attacker_set.clone();
        // Compromise honest nodes (spread out for max damage)
        for i in 0..compromised_count {
            let target = 1 + i * (N_HONEST / compromised_count);
            if !anchor_set.contains(&target) {
                attackers_total.insert(target);
            }
        }
        let total_att = attackers_total.len();
        let (net, wloss, acost) = attack(&quorums, &attackers_total, &deposits);
        let tag = if net > 0 { " STOLEN!" } else { "" };
        println!(
            "  Compromise {}: total_attackers={} ({}%), wallet_loss={}, cost={}, net={:+}{}",
            compromised_count,
            total_att,
            total_att * 100 / N,
            wloss,
            acost,
            net,
            tag
        );
    }
    println!();

    // --- Strategy 6: Attacker controls 49 total, all inside honest range ---
    // Best case: 49 of the 51 honest-appearing nodes are actually attacker
    // (only possible if attacker was there from the start)
    println!("=== Attacker Strategy 6: 49 of 51 'honest' nodes are actually attacker ===");
    {
        // Attacker controls nodes 1-49 (not anchors), only 0,50 + anchors are honest
        let mut insiders: HashSet<usize> = HashSet::new();
        let mut count = 0;
        for i in 0..N_HONEST {
            if count >= 49 {
                break;
            }
            if !anchor_set.contains(&i) {
                insiders.insert(i);
                count += 1;
            }
        }
        println!(
            "  Attacker controls {} of {} 'honest' nodes (anchors safe)",
            insiders.len(),
            N_HONEST
        );
        println!(
            "  Honest remaining: anchors + {} others",
            N_HONEST - insiders.len() - anch.len()
        );

        let (net, wloss, acost) = attack(&quorums, &insiders, &deposits);
        let tag = if net > 0 { " STOLEN!" } else { "" };
        println!(
            "  wallet_loss={}, cost={}, net={:+}{}",
            wloss, acost, net, tag
        );

        // How many nodes have attacker quorum majority?
        let compromised_quorums = (0..N_HONEST)
            .filter(|&i| {
                let ciq = quorums[i].iter().filter(|m| insiders.contains(m)).count();
                ciq >= quorums[i].len().div_ceil(2)
            })
            .count();
        let safe_quorums = N_HONEST - compromised_quorums;
        println!(
            "  Quorums with attacker majority: {}/{}",
            compromised_quorums, N_HONEST
        );
        println!("  Quorums still safe: {}", safe_quorums);
    }
    println!();

    println!("=== SUMMARY ===\n");
    println!("  When defender controls topology and wallet controls acceptance:");
    println!("  - External sybils: BLOCKED (can't get into honest quorums)");
    println!("  - Sybils with honest in quorum: BLOCKED (honest majority blocks theft)");
    println!("  - Compromised honest nodes: depends on count and placement");
    println!("  - 49/51 insider attack: the real threat");
}
