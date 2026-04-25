# Network Safety Strategies

Findings from adversarial topology analysis. The question: how do operators
and wallets protect deposits in a network where up to 49% of nodes may be
adversarial?

## The two defenses

Safety comes from two independent mechanisms that work together:

1. **Quorum formation** — operators choose who watches their ledger
2. **Wallet acceptance** — wallets decide where to deposit

Neither alone is sufficient. Together they defeat 49% adversarial control.

## Operator strategy: dispersed quorum selection

An operator's quorum members should be **spread across the network**, not
clustered together. In a ring of N honest nodes with quorum size Q:

- **Ring quorums** (adjacent members): vulnerable. A contiguous block of
  attackers controls every quorum in their range.
- **Dispersed quorums** (stride = N/(Q+1)): resistant. An attacker must
  control nodes at specific positions spread across the entire network to
  get majority of any single quorum.

With dispersed Q=5 quorums among 51 honest nodes, a 49% external attacker
achieves **zero wallet losses** regardless of their placement strategy.
Even compromising 25 honest nodes (72% total adversarial) is unprofitable
due to collateral slashing on the remaining honest ledgers.

The key property: each operator chooses their own quorum members. An
external attacker **cannot insert themselves** into an honest operator's
quorum. They can only form their own quorums — which honest wallets can
evaluate and reject.

### Minimum quorum requirements

Operators should select Q=5 quorum members with:
- Members spread across the honest network (stride >= N/(Q+1))
- No two members adjacent in the network graph
- Members chosen from operators the node has verified independently

## Wallet strategy: metric-based acceptance

The wallet sees the full quorum graph (public via Nostr relay data). Before
depositing, it computes metrics on the candidate operator's quorum.

### Primary metric: MinArc

**MinArc** = smallest contiguous arc of the network containing a majority of
the operator's quorum members.

- O(Q log Q) to compute
- Ring Q=5 quorum: MinArc = 2 (clustered, vulnerable)
- Dispersed Q=5 quorum: MinArc = 32 (spread, safe)
- Threshold: **MinArc >= N/Q** (majority spans at least 1/Q of the network)

MinArc directly measures resistance to adjacent-block attacks. If an
attacker needs to control nodes spanning 20% of the network to get quorum
majority, a contiguous 49% block only compromises a few quorums at its
boundaries.

### Secondary metric: quorum-mincut

**Quorum-mincut** = vertex connectivity from {quorum members as a group} to
{wallet's trust anchors}.

- O(V^3) to compute (multi-source/multi-sink max-flow)
- Measures how many independent paths connect the quorum to trusted oversight
- Sybil islands bottleneck through their bridges: quorum-mincut is low
- Honest dispersed quorums have high quorum-mincut (171+ in tested configs)

Quorum-mincut catches sybil attacks that MinArc alone might miss. A sybil
ring can mimic honest per-node metrics (clustering, individual mincut), but
the collective quorum-mincut reveals the bottleneck.

### Trust anchors

The wallet chooses its own trust anchors — operators it trusts through
out-of-band verification. Different wallets may have different anchors.
Anchors cannot be compromised in our threat model (they are the wallet's
root of trust, like trusting your SPV peer).

The number of anchors needed is modest: 6 anchors in a 100-node network is
sufficient for all tested scenarios.

### Wallet acceptance rules

1. Compute MinArc of the operator's quorum. Require **>= N/Q**.
2. Compute quorum-mincut to your anchors. Require **>= threshold**.
3. Verify the operator's quorum members are not all in the same cluster.
4. Re-check periodically (quorum memberships can change).

## What each defense stops

| Attack | Quorum formation | Wallet metric | Both |
|--------|:---:|:---:|:---:|
| Sybil island (external) | Blocks (can't join honest quorums) | Blocks (low MinArc/qmc) | Blocked |
| Sybil with honest in quorum | — | Accepts (looks legit) | **Blocked** (honest majority prevents theft) |
| Adjacent block (49%) | Blocks (dispersed quorums) | — | Blocked |
| Spread compromise (49%) | Blocks (slashing exceeds extraction) | — | Blocked |
| Compromised honest (72%) | Partially blocks | — | **Unprofitable** (slashing still exceeds) |
| Insider majority (88%+) | Fails | Fails | Stolen (but requires near-total compromise) |

## Economic underpinning

The collateral/reserves structure creates the economic defense:

- Each operator: 50% reserves on own ledger, 50% collateral split across Q
  quorum member ledgers
- Per-lock amount: UTXO / (2 * Q)
- Per-lock / reserves = 1/Q (33% for Q=3, 20% for Q=5)

When an attacker defects, they lose collateral on every honest ledger where
the honest quorum retains majority. With dispersed quorums, an attacker's
collateral is spread across many honest ledgers — the slashing exposure
grows faster than the extraction opportunity.

The formula for single-target theft: the attacker needs collateral slashing
< reserves stolen. With dispersed quorums, each coalition member's
collateral is at risk on ~Q honest ledgers, so total slashing exposure
scales as K * Q * per_lock. Extraction from a single target is bounded by
reserves. The crossover depends on the fraction of honest quorums that
retain majority — which dispersed topology maximizes.

## What doesn't work

Metrics and strategies we tested that failed:

- **Node mincut** (individual): identical for honest and sybil nodes. Does
  not detect sybil islands.
- **Clustering coefficient**: sybil rings mimic honest ring clustering
  (0.667 for both). Only catches sybil cliques, not sybil rings.
- **LConn** (local connectivity): sybils can fill the 2-hop neighborhood,
  making LConn look healthy.
- **Increasing collateral ratio**: does not change the safety threshold
  when topology is weak. Ring quorums are vulnerable at any collateral ratio.
- **Increasing Q**: helps but not necessary if quorum formation is
  dispersed. Q=5 with dispersed quorums beats Q=7 with ring quorums.

## Tested configurations

All findings verified by simulation in the `tests/tests/` directory:

| Test file | What it tests |
|-----------|--------------|
| `topology_metrics.rs` | Comparison of 8 metrics against mincut ground truth |
| `localconn_safety.rs` | LConn safety mapping across topologies |
| `localconn_attack.rs` | Full P&L attack simulation, collateral reuse sweep |
| `wallet_safety.rs` | Wallet acceptance policy with sybil island attacks |
| `wallet_steal.rs` | 7 attack strategies against mincut + clustering policy |
| `quorum_mincut_steal.rs` | 49% attack on 100-node network, quorum-mincut policy |
| `quorum_spread.rs` | MinArc vs quorum-mincut vs spread — which metric predicts safety |
| `defend_49pct.rs` | 5 honest topologies × 3 attack patterns × metric sweeps |
| `adversarial_placement.rs` | Defender vs attacker: free placement, 51 vs 49 nodes |

## Summary

The protocol is secure against 49% adversarial control when:

1. **Honest operators form dispersed quorums** among nodes they trust
2. **Wallets check MinArc >= N/Q** and quorum-mincut before depositing

The defense is not a single metric or parameter — it's the combination of
honest quorum formation (operators choose well-spread, verified members) and
wallet-side verification (reject clustered or poorly-connected quorums).

No topology metric alone detects all attacks. No economic parameter alone
prevents all attacks. But quorum formation + wallet metrics + collateral
economics together create a system where the attacker must compromise 70%+
of the honest network to profit — and even then, slashing makes it
expensive.
