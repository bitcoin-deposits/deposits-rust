//! Full collusion economics with multi-ledger operators.
//!
//! Each operator: 3 ledgers, U/4 reserves each, U/4 collateral.
//! Collateral split pro-rata across quorum memberships.
//! Coalition of K operators defect. Theft proceeds must exceed
//! total coalition losses for the attack to be rational.

use std::collections::HashSet;

const Q: usize = 5;
const U: u64 = 400_000; // UTXO per operator
const RESERVES_PER_LEDGER: u64 = U / 4;
const COLLATERAL: u64 = U / 4;
const EXT_DEPOSIT: u64 = RESERVES_PER_LEDGER; // wallets fund to max

fn rng_next(seed: &mut u64) -> usize {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    (*seed & 0x7FFFFFFF) as usize
}

struct Operator {
    id: usize,
    ledgers: [usize; 3],            // ledger IDs
    quorum_memberships: Vec<usize>, // ledgers this operator serves on as quorum member
}

struct Ledger {
    id: usize,
    owner: usize,
    quorum: Vec<usize>, // operator IDs (not ledger IDs)
}

struct Network {
    operators: Vec<Operator>,
    ledgers: Vec<Ledger>,
}

impl Network {
    fn build(n_operators: usize, seed: &mut u64) -> Self {
        let n_ledgers = n_operators * 3;
        let mut operators: Vec<Operator> = (0..n_operators)
            .map(|i| Operator {
                id: i,
                ledgers: [i * 3, i * 3 + 1, i * 3 + 2],
                quorum_memberships: Vec::new(),
            })
            .collect();

        // Each ledger gets Q quorum members (random operators, not self)
        let mut ledgers: Vec<Ledger> = (0..n_ledgers)
            .map(|lid| Ledger {
                id: lid,
                owner: lid / 3,
                quorum: Vec::new(),
            })
            .collect();

        for lid in 0..n_ledgers {
            let owner = lid / 3;
            let mut members = Vec::new();
            while members.len() < Q {
                let m = rng_next(seed) % n_operators;
                if m != owner && !members.contains(&m) {
                    members.push(m);
                }
            }
            ledgers[lid].quorum = members.clone();
            for &m in &members {
                if !operators[m].quorum_memberships.contains(&lid) {
                    operators[m].quorum_memberships.push(lid);
                }
            }
        }

        Network { operators, ledgers }
    }

    /// Simulate coalition defection. Returns per-member P&L.
    fn attack(&self, coalition: &HashSet<usize>) -> AttackResult {
        let n_ops = self.operators.len();

        // Per-operator tracking
        let mut gains = vec![0i64; n_ops]; // external deposits stolen
        let mut reserve_loss = vec![0i64; n_ops]; // reserves confiscated
        let mut collateral_loss = vec![0i64; n_ops]; // collateral slashed

        // For each ledger, determine outcome
        for ledger in &self.ledgers {
            let owner = ledger.owner;
            let is_coalition_owner = coalition.contains(&owner);

            let coal_in_q = ledger
                .quorum
                .iter()
                .filter(|m| coalition.contains(m))
                .count();
            let honest_in_q = ledger.quorum.len() - coal_in_q;
            let majority = ledger.quorum.len().div_ceil(2);
            let coalition_majority = coal_in_q >= majority;

            if is_coalition_owner {
                if coalition_majority {
                    // Coalition controls this ledger — steal external deposits
                    gains[owner] += EXT_DEPOSIT as i64;
                    // Owner keeps own reserves (already theirs)
                } else {
                    // Honest majority confiscates reserves, reassigns ledger
                    reserve_loss[owner] += RESERVES_PER_LEDGER as i64;
                }
            }
            // Non-coalition owners: if coalition has majority, they steal deposits
            // (but only if wallet funded this ledger — we'll handle with MinArc below)
            // For now: we only count theft from coalition members' own ledgers
            // because the question is about the coalition's own economics
        }

        // Collateral losses: each coalition member loses pro-rata on honest ledgers
        for &c in coalition {
            let op = &self.operators[c];
            let total_memberships = op.quorum_memberships.len();
            if total_memberships == 0 {
                continue;
            }

            let honest_memberships = op
                .quorum_memberships
                .iter()
                .filter(|&&lid| {
                    let ledger = &self.ledgers[lid];
                    // Is this ledger's quorum honest-majority?
                    let coal_in_q = ledger
                        .quorum
                        .iter()
                        .filter(|m| coalition.contains(m))
                        .count();
                    let honest_in_q = ledger.quorum.len() - coal_in_q;
                    honest_in_q >= ledger.quorum.len().div_ceil(2)
                })
                .count();

            // Pro-rata: lose honest_memberships/total_memberships of collateral
            let loss = COLLATERAL as f64 * honest_memberships as f64 / total_memberships as f64;
            collateral_loss[c] += loss as i64;
        }

        // Total coalition P&L
        let total_gain: i64 = coalition.iter().map(|&c| gains[c]).sum();
        let total_reserve_loss: i64 = coalition.iter().map(|&c| reserve_loss[c]).sum();
        let total_collateral_loss: i64 = coalition.iter().map(|&c| collateral_loss[c]).sum();
        let total_cost = total_reserve_loss + total_collateral_loss;
        let net = total_gain - total_cost;

        // Per-member: if they split proceeds evenly, is it worth it?
        let k = coalition.len() as i64;
        let per_member_gain = total_gain / k;
        let per_member_cost: Vec<i64> = coalition
            .iter()
            .map(|&c| reserve_loss[c] + collateral_loss[c])
            .collect();
        let worst_member_cost = per_member_cost.iter().max().copied().unwrap_or(0);

        AttackResult {
            total_gain,
            total_reserve_loss,
            total_collateral_loss,
            total_cost,
            net,
            per_member_gain,
            worst_member_cost,
            coalition_size: coalition.len(),
        }
    }
}

struct AttackResult {
    total_gain: i64,
    total_reserve_loss: i64,
    total_collateral_loss: i64,
    total_cost: i64,
    net: i64,
    per_member_gain: i64,
    worst_member_cost: i64,
    coalition_size: usize,
}

#[test]
fn collusion_economics() {
    let trials = 500;

    println!("\n=== COLLUSION ECONOMICS: multi-ledger operators ===");
    println!(
        "  U={}, reserves={}/ledger, collateral={}",
        U, RESERVES_PER_LEDGER, COLLATERAL
    );
    println!("  3 ledgers per operator, Q={}, {} trials\n", Q, trials);

    for n_operators in [20, 34, 50] {
        println!(
            "=== {} operators ({} ledgers) ===\n",
            n_operators,
            n_operators * 3
        );

        println!(
            "{:>6} {:>5} | {:>8} {:>8} {:>8} {:>+9} | {:>8} {:>8} | {:>5}",
            "Coal%", "K", "Gain", "ResLoss", "ColLoss", "Net", "PerMemG", "WorstC", "Prof"
        );
        println!("{}", "-".repeat(85));

        for coal_pct in [10, 20, 25, 30, 33, 40, 49] {
            let k = (n_operators * coal_pct / 100).max(2);

            let mut profitable = 0;
            let mut total_net: i64 = 0;
            let mut max_net: i64 = i64::MIN;
            let mut total_gain = 0i64;
            let mut total_rloss = 0i64;
            let mut total_closs = 0i64;
            let mut total_pmg = 0i64;
            let mut total_wmc = 0i64;

            for trial in 0..trials {
                let mut seed =
                    (trial + 1) as u64 * 997 + coal_pct as u64 * 31 + n_operators as u64 * 13;
                let net = Network::build(n_operators, &mut seed);

                // Coalition: first k operators
                let coalition: HashSet<usize> = (0..k).collect();
                let result = net.attack(&coalition);

                if result.net > 0 {
                    profitable += 1;
                }
                total_net += result.net;
                if result.net > max_net {
                    max_net = result.net;
                }
                total_gain += result.total_gain;
                total_rloss += result.total_reserve_loss;
                total_closs += result.total_collateral_loss;
                total_pmg += result.per_member_gain;
                total_wmc += result.worst_member_cost;
            }

            let t = trials as f64;
            let tag = if profitable == 0 {
                "safe"
            } else if profitable <= 5 {
                "~safe"
            } else {
                "BREAK"
            };

            println!(
                "{:>5}% {:>5} | {:>8.0} {:>8.0} {:>8.0} {:>+9.0} | {:>8.0} {:>8.0} | {:>3}/{} {}",
                coal_pct,
                k,
                total_gain as f64 / t,
                total_rloss as f64 / t,
                total_closs as f64 / t,
                total_net as f64 / t,
                total_pmg as f64 / t,
                total_wmc as f64 / t,
                profitable,
                trials,
                tag
            );
        }
        println!();

        // Detail: show one trial at 33%
        let k = n_operators * 33 / 100;
        let mut seed = 12345u64 + n_operators as u64;
        let net = Network::build(n_operators, &mut seed);
        let coalition: HashSet<usize> = (0..k).collect();
        let result = net.attack(&coalition);

        println!("  Detail (33%, K={}):", k);
        println!("    Gain (stolen ext deposits): {}", result.total_gain);
        println!(
            "    Reserve loss (confiscated):  {}",
            result.total_reserve_loss
        );
        println!(
            "    Collateral loss (slashed):   {}",
            result.total_collateral_loss
        );
        println!("    Net:                         {:+}", result.net);
        println!(
            "    Per-member gain (split):     {}",
            result.per_member_gain
        );
        println!(
            "    Worst member cost:           {}",
            result.worst_member_cost
        );
        println!(
            "    Per-member profitable:       {}",
            result.per_member_gain > result.worst_member_cost
        );

        // How many ledgers did coalition control?
        let coal_majority_ledgers = net
            .ledgers
            .iter()
            .filter(|l| {
                let ciq = l.quorum.iter().filter(|m| coalition.contains(m)).count();
                ciq >= l.quorum.len().div_ceil(2)
            })
            .count();
        let coal_owned_majority = net
            .ledgers
            .iter()
            .filter(|l| {
                coalition.contains(&l.owner) && {
                    let ciq = l.quorum.iter().filter(|m| coalition.contains(m)).count();
                    ciq >= l.quorum.len().div_ceil(2)
                }
            })
            .count();
        let coal_owned_total = k * 3;
        println!(
            "    Coalition ledgers with majority: {}/{} owned, {} total",
            coal_owned_majority, coal_owned_total, coal_majority_ledgers
        );
        println!();
    }
}
