# Chapter 7: Quorum and Collateral

> **Audience**: operators, wallet users (depositors evaluating quorum quality), developers
> **Prereqs**: chapters 1, 2
> **DEPs**: DEP-05

The protocol's central trust assumption — repeated from [Chapter 2](02-mental-model.md) so it stays in your mind while you read this one — is that the quorum of any given ledger contains at least one honest member. Not a majority. One. Everything in this chapter is engineering around that assumption: how the quorum is formed, what its members are paid for, what they have to lose, and why the structure makes the *aggregate* network honest even when no individual operator is assumed to be.

This chapter covers the formation rules, the collateral economics, and the policy constraints that make those rules load-bearing. It is the first chapter where the protocol's economic argument — *misbehavior is detectable, and detection costs the operator more than the misbehavior could ever earn them* — gets concrete.

## What a quorum is, from the operator's side

When an operator opens a new ledger, they don't pick neutral validators. They pick *other operators*. Specifically, they pick a small set of operators who already run their own ledgers, with their own collateral, and ask each one to co-sign updates on this new ledger.

Membership is a deal between two operators. The new ledger's operator gains a co-signing partner; the prospective member gains a small recurring fee from co-signing and the option (not the obligation) to take over the ledger if the operator misbehaves. Neither side puts up new capital. The member's skin in the game is collateral they've already posted on their *own* ledger; that collateral is slashable if they misbehave as a member here. The operator's skin in the game is the collateral on *this* new ledger, which the member has the right to confiscate if the operator misbehaves.

This is the load-bearing asymmetry. A member is not a passive validator waiting to flag bad behavior. A member is, in the whitepaper's phrasing, an "incentivized predator" — earning a steady trickle from co-signing fees in normal operation, watching for fraud proofs, and standing to inherit the operator's entire UTXO if a fraud proof fires. The fee trickle is small. The takeover windfall is large. The protocol does not need to assume members are altruistic; it only needs to assume members will respond to a profit opportunity larger than their current revenue.

For an operator, picking a quorum is therefore a discovery and reputation problem, not a key-management problem. You want members who are reachable enough to co-sign promptly (otherwise your ledger can't make progress); economically rational (so that the predator argument applies); and ideally not all owned by the same party (so a single attacker can't capture the whole quorum). The reference deployment uses Q=3 in tests and recommends 5–7 in production. The protocol caps Q at 8 — see below.

## The 40/60 split

Every ledger anchors to a single Bitcoin UTXO. That UTXO is split, by accounting, into two portions:

```
UTXO = reserves + collateral
     = deposit_capacity + security_bond
```

Both portions live in the same Taproot output (the same `TxOut.value`); the split is bookkeeping, not separate outputs. The operator declares both amounts in `LedgerOpen` and re-declares them at every `QuorumBegin`; the quorum members verify, before co-signing, that `reserves_amount_msats + collateral_amount_msats` equals the on-chain UTXO value in millisatoshis. If those numbers don't reconcile, the cosigners refuse.

The reference network uses a 40/60 reserves/collateral split. That number is not arbitrary. From the simulation evidence in PROPOSAL.md, it is the smallest collateral fraction that survives a 49% sybil-coalition attack with five ledgers per operator. Lighter collateral (50/50, 67/33, 80/20) leaves an attack budget. Heavier collateral (33/67) is also safe but wastes capital.

| Reserves | Collateral | L | Max safe sybil% |
|:---:|:---:|:---:|:---:|
| 50% | 50% | 1 | 29% |
| 50% | 50% | 5 | 39% |
| **40%** | **60%** | **5** | **49%** |
| 33% | 67% | 5 | 49% |

The simulation's adversary model is intentionally pessimistic: a single coordinated attacker who can form sybil-optimal (all-attacker) quorums on every ledger they operate, while honest operators pick quorum members blindly from the network. With 40/60 and L=5, no run in 500 trials made the attacker money. Once you accept the model, the choice of split is dictated by the data.

The 40/60 ratio isn't enforced by the protocol — operators can set any reserves/collateral split they want — but a wallet evaluating an operator should treat any split with collateral below 60% as a signal that the operator either disagrees with the simulation or is hoping to host fewer ledgers (smaller `L`, lower compounding security). Wallets and discovery services routinely surface the ratio.

The split is *baked into the script tree's accounting*, not into the script tree itself. The Taproot output the quorum controls doesn't know whether 4 BTC of its 10 BTC is "reserves" and 6 BTC is "collateral" — it's just 10 BTC of P2TR. The split lives in the ledger state. What this means is: a slashing event confiscates the entire UTXO (10 BTC); the new operator inherits the deposit obligations against the reserves portion (4 BTC owed to depositors); the remaining 6 BTC is the new operator's compensation for taking over. That residual is the collateral, and it's the operator's real loss. See [Chapter 5](05-onchain-transactions.md) for the script-path mechanics.

## Why quorums are restricted to Q ∈ {3, 5, 7}

`Q` counts cosigners only — the operator is not included in `Q`. So `Q=3` means 1 operator + 3 cosigners (4 keys total in the on-chain quorum vault).

Two numbers govern quorum size:

- `MAX_DISPUTANTS = 15` — the on-chain script's hard cap. The dispute lottery (see [Chapter 13](13-custody-lottery.md)) tags each member with a 4-byte pubkey prefix in the partial-reveal protocol; the script size grows superlinearly past 15 disputants and the bond ratio approaches 100% of disputed value. This is a wire-format constant.
- `MAX_QUORUM_SIZE_POLICY = 7` — the *policy* cap on `Q`. Combined with odd-only and ≥3, valid `Q` values are restricted to `VALID_QUORUM_SIZES = {3, 5, 7}` (odd-only so thresholds have a clean majority, ≥3 for meaningful redundancy).

The policy lives in `deposits-protocol/src/constants.rs` and is enforced in `Ledger::validate_operation`:

```rust
if let LedgerOperation::QuorumBegin { quorum_members, .. } = operation {
    let q = quorum_members.len(); // cosigner count, operator not counted
    if !VALID_QUORUM_SIZES.contains(&q) {
        return Err(DepositsError::ProtocolViolation { ... });
    }
}
```

The reasoning behind capping below the on-chain limit is operational caution. The lottery script supports up to N=15 disputants, but until the network has production reliability data — how often partial-reveal failures actually occur, how cosigners behave under load, what bond-ratio range is comfortable — running smaller quorums keeps the worst-case dispute cheap. With Q=7 (the largest allowed), the lottery has 7 disputants; the worst-case bond ratio is 6/7 ≈ 86%, and partial-reveal failure cases at p=0.99 per-party reveal stay below 1%.

Lifting the cap is one constant change. The protocol fuzzer and the test suite still exercise high-Q lottery scripts at N=11 and N=15 to keep the script-side machinery honest, so the day the cap is raised the validation has already been done.

**Disputants = Q.** When a fraud proof fires against an operator, the *operator* is the party being disputed and is structurally barred from arming on their own ledger (their signature wouldn't make sense; they're the one being slashed). This is enforced by `validate_update_signer`. The operator was never counted in `Q`, so disputants equal `Q` exactly — every cosigner is a potential disputant.

## Fee-schedule policy: members protect themselves from bad inheritance

When a member joins a quorum, they specify minimum fee terms the operator must respect. From DEP-05:

- `min_fee_bps`: minimum annualized fee rate, basis points
- `min_fee_fixed`: minimum annualized fixed fee, msats/year
- `max_fee_period`: maximum block-distance between fee collections
- `max_descriptor_bytes`: maximum miniscript descriptor size for deposits the member might inherit
- `membership_until`: block height at which this member's commitment ends

The strictest values across all members apply to the quorum as a whole. The operator cannot open a deposit (or accept a `FeeChange`) that violates the strictest member's minimums; cosigners will refuse to sign updates that do. The check lives in `deposits-core/src/operation_validation.rs:239` (`validate_fee_minimum`).

Why does the protocol care about member-side fee minimums? Because of *custody transfer*. If the operator on this ledger is ever slashed, the lottery winner inherits all the deposits and their fee schedules. A member who joined under the assumption that "this operator charges 50 bps annually" will, after a custody transfer, become the new operator (or a member of whoever wins) — and will inherit those same deposits at those same fee rates. If the original operator was free to negotiate sub-economic fees with depositors, the member would be inheriting unprofitable obligations. The fee minimums turn that into a precondition: a member's continued participation in the quorum is conditional on the operator never accepting work below the member's bottom line.

The same logic explains `max_descriptor_bytes` (a member can refuse to inherit absurdly large miniscript spending paths) and `max_transfer_timeout_blocks` (a member can refuse to inherit transfers that lock funds for unbounded periods). Each minimum is a guarantee the operator owes their quorum: "if the worst happens and you take over, you will not be left holding obligations you would never have signed up for."

Members also negotiate compensation — `compensation_bps` is the fraction of operator-collected fees that flows to each member, default 300 bps (3%) per member. With Q=7 members at default, ~21% of fee revenue is distributed to cosigners. This is the steady-state side of the predator equation: the small fee trickle that pays for the watchful eye.

## The quorum lifecycle

The quorum has a state machine:

```text
PreQuorum
  │  - Operator-only signatures (no co-signing)
  │  - QuorumAddMember stages members
  │
  │ QuorumBegin (rotates reserves UTXO)
  ▼
Active
  │  - Co-signatures required for all updates
  │  - Full deposit operations allowed
  │  - Must re-rotate before quorum_expiry
  │
  ├─── QuorumBegin ──► Active (re-rotation)
  │
  └─── expiry passes ──► Expired (non-conforming)
```

(Reproduced from `deposits-protocol/src/types/core.rs:653`.)

A new ledger starts in `PreQuorum`. In this state, the operator can sign updates alone — there is no quorum yet. The only things they can usefully do are open the ledger (`LedgerOpen`) and stage members (`QuorumAddMember`, discriminator 43). Each `QuorumAddMember` does *not* grant voting power; it appends the member to a pending list (`next_quorum_members` in the state model). The member, on their *own* ledger, appends a `QuorumJoin` (disc 46) to record the agreement from their side. The two operations together form a two-sided auditable record.

The `QuorumBegin` operation (disc 12) is the atomic transition. It does two things at once:

1. **Promotes the staged set wholesale.** Every member in `next_quorum_members` becomes active. Anything *not* in the staged set is dropped — including currently active members the operator forgot to re-stage. This is intentional: refreshing a quorum requires explicitly re-staging every member you want to keep.
2. **Rotates the on-chain multisig.** The operator spends the old reserves UTXO (or the genesis funding UTXO, on first activation) into a new Taproot output whose script paths reflect the new active member set. This is where the on-chain lottery script gets re-built; see [Chapter 5](05-onchain-transactions.md).

The first `QuorumBegin` (the one that transitions `PreQuorum` → `Active`) is special. It must itself carry cosignatures from `floor(n/2) + 1` of the staged set — even though there's no active quorum yet to demand them. Without this rule, the operator could unilaterally activate the ledger with a fabricated member list, since pre-activation there's no one to refuse. The protocol forces the staged members to attest the rotation before it counts. Cosigners on this first `QuorumBegin` MUST also verify that the declared reserves UTXO actually exists on-chain, is unspent, carries the declared value, and has a network-dependent minimum number of confirmations (6 on mainnet, 1 on regtest, configured via `default_quorum_begin_confs` in `deposits-core/src/quorum_policy.rs`).

After the first `QuorumBegin`, every subsequent ledger update needs `floor(n/2) + 1` cosignatures from distinct members. This is what makes parallel chains impossible: a majority of cosigners has seen and validated the canonical chain before signing any new update; if the operator tried to obtain a majority for two updates at the same sequence number, at least one member of any majority would already have signed the other version and refuse the second.

**Adding a member.** `QuorumAddMember` appended to an active quorum *stages* the new member into `next_quorum_members`. They have no voting power until the next `QuorumBegin` promotes the staged set. This lets an operator add several members across separate ledger updates and activate them together with a single rotation.

**Removing a member.** `QuorumRemoveMember` (disc 44) is *immediate*. The named member is dropped from both the active set and the pending set on apply. No subsequent `QuorumBegin` is required for the member to lose ledger-level voting rights. The on-chain Taproot script, however, still encodes the pre-remove member set until the next `QuorumBegin` rotates it — so on-chain spends still need the departing member's signature in the meantime. This window is uncomfortable but bounded: operators typically follow a `QuorumRemoveMember` with a `QuorumBegin` in the next ledger update.

The asymmetry between add and remove is deliberate. Adding is staged because adding is usually a planned, capacity-building action — the operator wants to bring on multiple members and start them together. Removing is immediate because removing usually means a member misbehaved, went silent, or otherwise needs to be stripped of veto power *now*. Forcing the operator to wait until the next rotation to remove a captured member would let the captured member keep blocking updates in the meantime.

**Quorum expiry.** Each member's `membership_until` block is a commitment expiry. The shortest member's `membership_until` becomes the quorum's `quorum_expiry`. Before this block, the operator MUST refresh the quorum via a new `QuorumBegin`. If the block passes without a refresh, the ledger's state transitions to `Expired` and is non-conforming — at that point any quorum member can initiate dispute.

**In-flight operations during a quorum change.** A `QuorumBegin` does not freeze the ledger; it lands at a specific sequence number, just like any other update. Operations committed before that sequence number are validated against the *old* active member set; operations after are validated against the *new* active member set. Pending transfers and invoices persist across the rotation — their state is part of the ledger's deposit data, not part of the quorum's membership.

## The economic deterrence argument

This section is the whole point. Strip away the wire formats and the script trees, and what's left is:

> **Members are paid steadily; members win big if the operator falls.**

Steady income comes from `compensation_bps` — the per-member share of operator fees, default 3%, paid out at `compensation_frequency_blocks` (default ~2 weeks). Cosign Lightning payments, on-chain deposits, and intra-ledger transfers all generate fees, and a fraction of those flow to each member's deposit on the operator's ledger.

Big-win income comes from *successful recovery*. When a fraud proof fires and the recovery pipeline runs to completion (Chapter 12), the lottery (Chapter 13) elects exactly one member as the new custodian. That member wins:

- The reserves portion of the operator's UTXO — but they also inherit the deposit obligations against it. Net: zero, in expectation. (This is the "self-fill neutralizes reserve confiscation" point from PROPOSAL.md — operators can fill their own reserves with self-deposits, so confiscating reserves recovers self-deposit obligations.)
- The collateral portion — kept outright. *This is the prize.* No corresponding obligation is inherited.

So the predator's payoff is approximately the slashed operator's collateral. With a 40/60 split and a 10 BTC UTXO, that's 6 BTC dropped into the lottery winner's lap.

The asymmetry is what drives the simulation's 49% threshold. From the whitepaper:

> simulation shows that with a 40/60 reserves/collateral split and multiple ledgers per operator with independent quorums, this attack is unprofitable for coalitions controlling up to 49% of the network. the key mechanism: each colluding operator whose own quorum retains honest majority loses their collateral, and with independent quorums the probability of escaping all of them drops exponentially with the number of ledgers.

In a sybil-optimal attack, the attacker controls some fraction of operators and tries to assemble all-sybil quorums on as many of their ledgers as possible. The attacker's gain is the reserves they can self-fill and steal; the attacker's loss is the collateral on every one of their ledgers where the quorum retained honest majority. With the 40/60 split, every ledger compromised gains the attacker `0.4 × U / L` and every ledger slashed costs them `0.6 × U / L` — a net loss per slashed ledger that exceeds the gain per stolen one. Combine with multi-ledger compounding (next section) and 49% becomes the break-even point.

The simulation file is `deposits-test/tests/defend_49pct.rs`. It runs explicitly: an N=50 operator population, Q=5 quorums, 500 trials per parameter point, with a sybil-optimal attacker. At 49% adversarial control, zero of 500 runs were profitable. At 50%, some are. The number isn't a slogan; it's the empirical inflection.

## Multi-ledger operators and quorum independence

The simulation's other knob is `L` — the number of independent ledgers per operator. The recommendation in DEP-05 is 3–5. The structural reason is that the same UTXO, split across L ledgers each with an *independent* quorum, gives the network multiplicative security:

- The attacker must compromise *all L* of an operator's ledgers' quorums to escape losing collateral. Anything less and at least one honest quorum slashes.
- If quorums are random and independent, and the attacker controls fraction `s` of the network, the per-ledger probability of an all-sybil quorum is roughly `s^Q`. The probability of escaping all L ledgers is `s^(QL)`.

With Q=5 and L=5 and s=33%, the per-quorum compromise probability is ~0.4%; the per-operator escape probability is ~10⁻¹². With L=1 the same adversarial fraction has a 0.4% chance per operator. The compounding is the point.

What "independent" means here is graph-theoretic. If operator A's five quorums all overlap heavily (the same ten members rotated across all five), the quorums aren't independent and the compounding fails. Wallets evaluate this with metrics like `quorum-mincut` — the vertex-connectivity of the operator's quorums to the wallet's trusted anchor set. High mincut = independent quorums = compounding security. Low mincut = a single attacker capturing one node can capture multiple ledgers at once.

This is also why the protocol does not pick quorum members for the operator. A quorum is a graph-positioning decision, and only the operator (and the wallets watching) have visibility into the topology. The protocol enforces *what* a quorum must do; it leaves *who* is in it to the operator and the wallet's discovery preferences.

## The trust assumption, reiterated

To repeat the load-bearing sentence one more time so it sticks:

> The quorum of any given ledger contains at least one honest member.

Not a majority. One.

The reason "one" is enough: a single honest member can produce a fraud proof, and once a fraud proof is publicly broadcast, *every* member of the quorum has the same upside if they participate in the recovery (the lottery elects one of them; their odds are equal). A single honest detector is sufficient to trigger the cascade; the predators will line up behind them not out of altruism but because the lottery is winnable.

If the assumption fails — if every member of a quorum is captured by the same attacker as the operator — that ledger's deposits are stolen. The network cannot save them. What the network *can* do is make multi-ledger collusion expensive enough that the attack is unprofitable, by ensuring that every captured operator pays slashing on the *other* ledgers they run where the quorum is not also captured. Independent quorums + 40/60 split + L=5 + 49% sybil ceiling: that's the engineering bound that makes "at least one honest member per quorum" survivable as a network-wide assumption even when no individual quorum can be guaranteed.

This is the protocol's whole bet. Custody at scale, without unilateral exit's on-chain footprint and without a federation's hand-wave, by aligning the predators' incentives with the depositors'.

## Where this leads

The next chapter, [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md), is the operator-facing inverse of this one: now that you know who has the keys and what they have to lose, the next chapter walks through the operations wallets actually invoke against a quorum-active ledger. Deposit opening, intra-ledger transfers, lock/fulfill/fail state machines, and how the cosignature requirement from this chapter shows up at every step.
