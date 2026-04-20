# Proposal: Collateral-in-UTXO

## Summary

Change collateral from a deposit on quorum members' ledgers to a portion of the operator's own UTXO, held in the same Taproot output as reserves and controlled by the operator's quorum.

## Motivation

Adversarial topology analysis revealed that the current collateral model (separate deposits on other ledgers, with reuse) has two problems:

1. **Pro-rata dilution**: collateral split across quorum memberships reduces per-ledger slashing power. With Q=5 and 3x reuse, effective per-lock is U/2/Q/3 — too thin to deter theft at >30% sybil.

2. **Self-fill neutralizes reserve confiscation**: operators can fill their own ledger with self-deposits via lightning. On confiscation, the new operator owes those deposits back. The rogue operator recovers their reserves, making confiscation costless. This eliminates the largest cost component in the attack economics.

With collateral-in-UTXO, slashing is binary and local: misbehave → your own quorum takes your collateral. No pro-rata splitting across memberships. The collateral is real capital that cannot be recovered via self-fill.

## Design

### Per-operator structure

Each operator has one UTXO per ledger, held in the quorum's Taproot output:

```
UTXO = reserves + collateral
     = deposit_capacity + security_bond
```

Only the reserves portion is available as deposit capacity. The collateral portion cannot be used for deposits — it's the operator's bond against misbehavior.

### Slashing mechanism

When an operator misbehaves (as detected by quorum members on any ledger they serve on), the operator's own quorum slashes their collateral:

- The quorum controls the UTXO via Taproot
- Honest majority on the operator's OWN ledger can confiscate the collateral
- The confiscating quorum member takes over the ledger and its reserves/deposits
- The collateral is the real cost — it cannot be recovered via deposit claims

### Multiple ledgers

Operators run L ledgers, each with independent quorums. The UTXO is split:

- Total reserves = U × reserves_fraction, divided across L ledgers
- Total collateral = U × collateral_fraction, divided across L ledgers
- Each ledger has an independent Q=5 quorum

When an operator goes rogue on one ledger, the other ledgers' quorums detect this and slash. The operator must compromise ALL L quorums simultaneously to avoid losing collateral — probability P(single quorum compromised)^L.

### Quorum membership

Serving on another operator's quorum does NOT require separate capital. The cost of misbehavior as a quorum member is slashing on your OWN ledger(s). This means:

- No collateral deposits on other ledgers
- No reuse limits
- Quorum membership is lightweight (just attestation + monitoring)
- Minimum requirement: operator must have at least collateral/2 at stake on their own ledger(s)

## Parameters

Simulated configurations (N=50 operators, Q=5, 500 trials, sybil-optimal attacker, blind honest quorum formation, self-fill assumed):

| Reserves | Collateral | Efficiency | L=1 | L=3 | L=5 | L=7 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 80% | 20% | 80% | 5% | 9% | 13% | 15% |
| 67% | 33% | 67% | 11% | 21% | 23% | 21% |
| 50% | 50% | 50% | 29% | 35% | 39% | 41% |
| 45% | 55% | 45% | 33% | 43% | 45% | 47% |
| 40% | 60% | 40% | 41% | 47% | 49% | 49% |
| 33% | 67% | 33% | 47% | 49% | 49% | 49% |

Values are maximum sybil percentage where 0/500 trials were profitable.

### Recommended configurations

**Conservative launch (33/67, L=3)**:
- 33% capital efficiency (3:1 lockup)
- Safe through 49% single-coalition sybil
- Suitable for early network with unknown operator composition

**Growth (40/60, L=5)**:
- 40% capital efficiency (2.5:1 lockup)
- Safe through 49% sybil
- Suitable once operator set is partially established

**Mature network (50/50, L=5)**:
- 50% capital efficiency (2:1 lockup, same as lightning channels)
- Safe through 39% single-coalition sybil
- Suitable for larger networks where >39% coordinated attack is unrealistic

## Assumptions and limitations

**Self-fill**: operators are assumed to fill their own ledgers with self-deposits. Reserve confiscation is therefore not a real cost. Only collateral slashing deters theft.

**Single coalition**: the sybil percentage assumes one coordinated attacker. Multiple independent attackers are much less effective because they can't coordinate quorum control.

**Random quorum formation**: honest operators pick quorum members randomly from the network (they cannot distinguish honest from sybil). The attacker knows who they control and forms optimal (all-sybil) quorums.

**Binary slashing**: if an operator's own quorum has honest majority, the full collateral on that ledger is slashed. No partial slashing or pro-rata across memberships.

**Wallet sybil detection**: results assume wallet can avoid depositing on sybil-operated ledgers (via MinArc or similar metric). Without this, the attacker also profits from deposits placed directly on sybil nodes.

## Changes required

### deposits-protocol

- Ledger state: add `collateral_amount` field alongside reserves
- Conformance: reject deposits that would exceed `reserves_amount` (not total UTXO)

### deposits-core

- Taproot output: collateral portion must be spendable by quorum majority for slashing
- Validation: enforce reserves + collateral = UTXO value
- Slashing: new dispute path that confiscates collateral and reassigns ledger

### deposits-node

- Quorum membership: no longer requires posting collateral deposits on other ledgers
- Monitoring: detect misbehavior by operators whose quorums include this node
- Slashing initiation: trigger collateral confiscation on misbehaving operator's own ledger

## Code changes required

~450 occurrences across 50 files reference the old collateral model. The changes group into:

### Remove (old collateral model)

Removed operations and fields:
- collateral-deposit-type flag on `DepositOpen` — collateral is no longer a deposit type
- `collateral_lock_amount`, `collateral_lock_until` on `QuorumAddMember`
- `for_ledger_id` / `collateral_ledger_id` — no cross-ledger collateral
- `total_collateral` field on `QuorumBegin` (replaced by `collateral_amount_msats`)

Affected crates:
- `deposits-protocol`: types, messages, TLV codec (~100 occurrences)
- `deposits-core`: ledger state, validation, operation handling (~80 occurrences)
- `deposits-node`: operations, coordination, CLI commands (~80 occurrences)
- tests across all crates (~190 occurrences)

### Add (new collateral model)

- `collateral_amount_msats` field on `LedgerOpen` and `QuorumBegin`
- Co-signer validation: `reserves_amount_msats + collateral_amount_msats == UTXO value`
- Co-signer check: reject operations that reduce UTXO below the sum
- Punitive confiscation path: full UTXO to lottery winner
- Cross-ledger slashing: present fraud proof from ledger A to quorum on ledger B

### Rename

- `reserves_amount` → `reserves_amount_msats` (consistency with `_msats` convention)

### Test files to remove or rewrite

- `collateral_deposit_test.rs` — collateral deposits no longer exist
- `attack_collateral_reuse.rs` — reuse model replaced
- `quorum_fee_limits_test.rs` — collateral lock terms removed from member terms

## Simulation evidence

All findings derived from Monte Carlo simulations in `tests/tests/`:

- `collusion_econ.rs` — multi-ledger collusion economics
- `final_game.rs` — sybil-optimal attacker vs blind honest quorums
- `turn_game.rs` — turn-based placement with anchor endorsement
- `quorum_spread.rs` — wallet metrics for sybil detection
- `defend_49pct.rs` — topology × metric sweeps across attack patterns

The simulations model: random quorum formation, sybil-optimal attacker (all-sybil quorums), self-filled reserves, binary collateral slashing, and wallet deposits on honest operators only.
