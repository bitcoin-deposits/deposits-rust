//! Detailed collusion analysis: trace every step for every coalition size.
//!
//! For each (N, Q, K), answer:
//! 1. How many coalition members are in each honest operator's quorum?
//! 2. Can the honest majority in that quorum still dispute?
//! 3. Can they still confiscate reserves (Taproot threshold spend)?
//! 4. What does each side's balance sheet look like after the attack?

use deposits_test::adversarial::*;

/// Detailed per-ledger analysis for a coalition attack.
#[derive(Debug)]
struct LedgerAttackDetail {
    operator_idx: usize,
    is_coalition: bool,
    quorum_members: Vec<usize>,
    coalition_in_quorum: usize,
    honest_in_quorum: usize,
    honest_have_majority: bool,
    /// Can honest members meet Taproot tier-0 threshold (majority immediate)?
    honest_can_confiscate: bool,
    /// What happens to this ledger's deposits?
    deposits_safe: bool,
}

fn analyze_detailed(n: usize, q: usize, coalition: &[usize]) -> Vec<LedgerAttackDetail> {
    let coalition_set: std::collections::HashSet<usize> = coalition.iter().copied().collect();
    let mut details = Vec::new();

    for i in 0..n {
        // This operator's quorum: Q neighbors in round-robin
        let quorum: Vec<usize> = (1..=q).map(|j| (i + j) % n).collect();

        let coalition_in_q = quorum.iter().filter(|m| coalition_set.contains(m)).count();
        let honest_in_q = quorum.len() - coalition_in_q;

        // Taproot tier-0: majority immediate = ceil((Q+1)/2) signers
        // But the operator (tie-breaker) is NOT in the quorum — they're the one being disputed
        // So the quorum members need to meet the threshold WITHOUT the operator
        let majority_needed = q.div_ceil(2); // majority of Q members
        let honest_majority = honest_in_q >= majority_needed;

        // For Taproot confiscation, the tier-0 script requires majority of voters
        // If operator is coalition, honest quorum members need to outvote coalition members
        let honest_confiscate = honest_majority; // same threshold for now

        let is_coal = coalition_set.contains(&i);
        let deposits_safe = if is_coal {
            // Coalition operator steals their own deposits — deposits NOT safe
            false
        } else {
            // Honest operator's deposits are safe IF their quorum can still dispute
            honest_majority
        };

        details.push(LedgerAttackDetail {
            operator_idx: i,
            is_coalition: is_coal,
            quorum_members: quorum,
            coalition_in_quorum: coalition_in_q,
            honest_in_quorum: honest_in_q,
            honest_have_majority: honest_majority,
            honest_can_confiscate: honest_confiscate,
            deposits_safe,
        });
    }

    details
}

#[test]
fn collusion_detail_small_network() {
    println!("\n=== Detailed Collusion: N=8, Q=3 ===\n");

    let n = 8;
    let q = 3;
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    for k in 1..=n {
        // Coalition is operators 0..k
        let coalition: Vec<usize> = (0..k).collect();
        let details = analyze_detailed(n, q, &coalition);

        let coalition_ledgers: Vec<_> = details.iter().filter(|d| d.is_coalition).collect();
        let honest_ledgers: Vec<_> = details.iter().filter(|d| !d.is_coalition).collect();

        // Coalition steals from their own ledgers
        let coalition_stolen = coalition_ledgers.len() as u64 * reserves;

        // Honest ledgers where quorum is compromised (coalition has majority)
        let honest_compromised: Vec<_> = honest_ledgers
            .iter()
            .filter(|d| !d.honest_have_majority)
            .collect();

        // Coalition can also steal from honest ledgers where they control quorum
        let honest_stolen = honest_compromised.len() as u64 * reserves;

        // Collateral at risk: coalition's collateral on honest ledgers that CAN still slash
        let honest_can_slash: Vec<_> = honest_ledgers
            .iter()
            .filter(|d| d.honest_have_majority)
            .collect();
        // How much coalition collateral is on those ledgers?
        // Each coalition member has collateral on their neighbors' ledgers
        // Simplified: coalition member i has collateral on quorum members of other ledgers
        let collateral_slashed = honest_can_slash.len() as u64 * collateral; // rough

        let total_extracted = coalition_stolen + honest_stolen;
        let net = total_extracted as i64 - collateral_slashed as i64;

        println!(
            "K={}: coalition=[0..{}], stolen_own={}M, honest_compromised={}, honest_stolen={}M, collateral_lost={}M, net={:+}M",
            k, k,
            coalition_stolen / 1_000_000,
            honest_compromised.len(),
            honest_stolen / 1_000_000,
            collateral_slashed / 1_000_000,
            net / 1_000_000,
        );

        // Print per-ledger detail for interesting cases
        if k == 1 || k == 2 || k == 4 || k == n {
            for d in &details {
                let marker = if d.is_coalition { "COAL" } else { "honest" };
                let quorum_str: Vec<String> = d
                    .quorum_members
                    .iter()
                    .map(|m| {
                        if coalition.contains(m) {
                            format!("*{}*", m)
                        } else {
                            format!("{}", m)
                        }
                    })
                    .collect();
                println!(
                    "  op_{} [{}]: quorum=[{}] coal={}/{} honest_majority={} safe={}",
                    d.operator_idx,
                    marker,
                    quorum_str.join(","),
                    d.coalition_in_quorum,
                    q,
                    d.honest_have_majority,
                    d.deposits_safe,
                );
            }
            println!();
        }
    }
}

#[test]
fn collusion_detail_medium_network() {
    println!("\n=== Detailed Collusion: N=16, Q=5 ===\n");
    println!(
        "{:>2} | {:>5} | {:>6} | {:>11} | {:>11} | {:>7} | {:>6}",
        "K", "K/N%", "Stolen", "Hon.Compromised", "Hon.Stolen", "Slashed", "Net"
    );
    println!("{}", "-".repeat(70));

    let n = 16;
    let q = 5;
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    for k in 1..=n {
        let coalition: Vec<usize> = (0..k).collect();
        let details = analyze_detailed(n, q, &coalition);

        let honest_count = details.iter().filter(|d| !d.is_coalition).count();
        let honest_compromised = details
            .iter()
            .filter(|d| !d.is_coalition && !d.honest_have_majority)
            .count();
        let honest_safe = details
            .iter()
            .filter(|d| !d.is_coalition && d.honest_have_majority)
            .count();

        let coalition_stolen = k as u64 * reserves;
        let honest_stolen = honest_compromised as u64 * reserves;
        let collateral_slashed = honest_safe as u64 * collateral;
        let total = coalition_stolen + honest_stolen;
        let net = total as i64 - collateral_slashed as i64;

        println!(
            "{:>2} | {:>4.0}% | {:>4}M | {:>4}/{:>4} honest | {:>5}M | {:>4}M | {:>+5}M {}",
            k,
            k as f64 / n as f64 * 100.0,
            coalition_stolen / 1_000_000,
            honest_compromised,
            honest_count,
            honest_stolen / 1_000_000,
            collateral_slashed / 1_000_000,
            net / 1_000_000,
            if net > 0 { "PROFITABLE" } else { "" },
        );
    }
}

#[test]
fn collusion_detail_large_network() {
    println!("\n=== Detailed Collusion: N=100, Q=7 ===\n");
    println!(
        "{:>3} | {:>5} | {:>6} | {:>13} | {:>6} | {:>7} | {:>7}",
        "K", "K/N%", "Stolen", "Compromised", "H.Stolen", "Slashed", "Net"
    );
    println!("{}", "-".repeat(65));

    let n = 100;
    let q = 7;
    let reserves = 1_000_000u64;
    let collateral = 500_000u64;

    // Sample interesting points
    for k in (1..=100).filter(|k| *k <= 10 || *k % 5 == 0 || *k >= 95) {
        let coalition: Vec<usize> = (0..k).collect();
        let details = analyze_detailed(n, q, &coalition);

        let honest_count = details.iter().filter(|d| !d.is_coalition).count();
        let honest_compromised = details
            .iter()
            .filter(|d| !d.is_coalition && !d.honest_have_majority)
            .count();
        let honest_safe = details
            .iter()
            .filter(|d| !d.is_coalition && d.honest_have_majority)
            .count();

        let coalition_stolen = k as u64 * reserves;
        let honest_stolen = honest_compromised as u64 * reserves;
        let collateral_slashed = honest_safe as u64 * collateral;
        let total = coalition_stolen + honest_stolen;
        let net = total as i64 - collateral_slashed as i64;

        println!(
            "{:>3} | {:>4.0}% | {:>4}M | {:>5}/{:>5} | {:>4}M | {:>5}M | {:>+6}M {}",
            k,
            k as f64 / n as f64 * 100.0,
            coalition_stolen / 1_000_000,
            honest_compromised,
            honest_count,
            honest_stolen / 1_000_000,
            collateral_slashed / 1_000_000,
            net / 1_000_000,
            if net > 0 { "PROFIT" } else { "" },
        );
    }
}
