# Chapter 10: Fees and Time Obligations

> **Audience**: operators (especially), wallet users, integrators
> **Prereqs**: chapters 4, 7, 8
> **DEPs**: DEP-07, DEP-11

The previous two chapters described what wallets do on a ledger: open deposits, lock and complete transfers, fulfill invoices. This chapter is about the economic plumbing that runs underneath all of those operations.

Two questions drive every choice in this chapter:

1. **How does the operator get paid?** They are running custody as a business; the protocol has to define a fee surface that lets them earn enough to cover collateral cost-of-capital plus operations, without giving them the freedom to abruptly jack rates on funds that are already deposited.
2. **How does the protocol talk about deadlines?** Half of the operator's slashable obligations are time-shaped — credit this on-chain offer before block N, fail this transfer before block M, rotate quorum before block K. Without a stable notion of "before" the fraud proofs in [Chapter 11](11-fraud-proofs.md) cannot be evaluated.

The two questions answer each other. The operator's earnings model is a stream of deadline-anchored fees; the time obligation system is what makes those fees enforceable in either direction. So the chapter takes them together.

## The fee schedule shape

Every deposit on the ledger carries its own fee schedule. There are two kinds of fee, layered on top of each other.

The first is **periodic custody fees** — what's sometimes called rent. Holding a balance on someone else's books costs something to the operator (collateral cost-of-capital, on-chain fees on rotations, hosting, member compensation), and that cost is recovered as a slow drip against the deposit's balance. The shape is `FeeStructure` in `deposits-protocol/src/types/core.rs:88`:

```rust
pub struct FeeStructure {
    pub annualized_msats: u64,   // fixed yearly fee (msats)
    pub annualized_bps: u16,     // proportional yearly rate (basis points)
    pub frequency_blocks: u32,   // collection cadence (blocks)
}
```

The fee for a collection period is computed pro-rata over `blocks_elapsed` since the last assessment:

```
fixed_portion       = annualized_msats * blocks_elapsed / 52560
proportional_portion = balance * annualized_bps * blocks_elapsed / (52560 * 10_000)
total_fee            = fixed_portion + proportional_portion
```

The constant `52560` is `365.25 * 144` — the conventional blocks-per-year used throughout the codebase. The default `frequency_blocks` is `2016`, about two weeks at typical block intervals.

DEP-07 is explicit about an arithmetic gotcha: the multiplicative chain `balance * annualized_bps * blocks_elapsed` overflows u64 for realistic whale balances (10¹⁶ msats × 10000 bps × a few thousand blocks). `FeeStructure::calculate_fee` widens to u128 for the multiply and saturates the downcast at the end. A naive u64 implementation would silently wrap and let the operator collect a tiny fraction of the intended fee — which sounds like a bug in the operator's favor, but is actually a non-conforming output the quorum would refuse to cosign. The widening is mandatory.

The second kind of fee is **per-transfer**, defined by `TransferFeeSchedule` in the same file:

```rust
pub struct TransferFeeSchedule {
    pub fixed_msats: u64,
    pub rate_bps: u16,
}
```

with `fee = fixed_msats + (amount * rate_bps / 10_000)`. This is the fee the wallet pays whenever a `TransferLock` resolves. The wallet quotes the exact fee in the lock request — operator rejects mismatches — and the operator collects on `TransferComplete` (full fee) or `TransferFail` (just `fixed_msats`, since no amount actually moved). The same wide-integer requirement applies.

There's an important asymmetry on the failure paths. `TransferFail`, `InvoiceFail`, and `OnchainFail` all charge `fixed_msats` even though no value moved, on the rationale that the operator did real work holding the lock. Implementations use saturating subtraction in case the deposit's balance dipped below `fixed_msats` between lock and fail. None of these failure-fee paths are optional — fuzz-found bugs in this area (see commit `e6fe801` for `OnchainFail` missing the unlock that was supposed to release locked balance) tell you these accounting paths are load-bearing and easy to get wrong.

## Where the fees land

Fees do not flow to a separate operator-balance field. Each ledger carries a single `fees_accumulated: u64` counter on `LedgerState` (`deposits-protocol/src/types/ledger_state.rs:96`):

```rust
/// Running total of fees the operator has accrued on this ledger
/// (msats), across both maintenance fees (FeeCollect) and per-transfer
/// fees captured on TransferComplete. On-chain withdrawal fees are
/// *not* included — those go to miners, not the operator.
pub fees_accumulated: u64,
```

Every fee-bearing operation `saturating_add`s into this counter. It is monotonically non-decreasing and never debited by the current implementation. DEP-07 calls it the substrate for a future quorum-member compensation payout: members are entitled to a percentage of `fees_accumulated` (per their `compensation_bps` recorded at quorum-join time), and the operator will ultimately distribute that share via a payout operation that debits the counter. The accounting machinery is in place; the payout op itself is not yet specified.

The operator's actual on-ledger profit is `fees_accumulated` minus any future member-compensation payouts. It does not appear as a deposit they can spend out of. To realize cash, the operator either rotates the reserves UTXO (taking fee income out as on-chain change) or holds it as un-withdrawn ledger state until a payout pathway lands.

One thing this counter does *not* include: `OnchainLock.fee_sats`, the miner fee on on-chain withdrawals. That goes to the Bitcoin miner, not the operator. DEP-07 calls this out explicitly so nobody mistakenly counts it as operator income.

## What the wallet sees at deposit-open

A `DepositOpen` operation embeds the deposit's full fee schedule, including the fee-change governance parameters (more on those in a moment). Once the deposit is open, the schedule is bound to it: one deposit, one schedule. Two deposits on the same ledger can have different fees, which is how operators offer tiered service (smaller default deposits at the cheap rate, bespoke rates for whales).

The wallet doesn't open a deposit blind. The operator advertises a `LedgerAdvertisement` on Nostr (`deposits-node/src/nostr.rs`) that publishes their **minimum fees** — the floor below which they won't accept a deposit. The wallet may propose anything at or above the floor; the operator validates against it via `validate_fee_minimum` (`deposits-core/src/operation_validation.rs:239`):

```rust
pub fn validate_fee_minimum(
    proposed: &FeeStructure,
    min_annual_bps: u16,
    min_fixed_per_period: u64,
) -> ValidationResult { ... }
```

A proposed schedule below the operator's floor is rejected at the request layer before any cosign goes out.

## The member fee floor

This is the part of the fee system that is most easy to miss but most consequential. Each quorum member, when they join via `QuorumAddMember`, declares minimum fees they require for membership: `min_fee_bps`, `min_fee_fixed`, and a `max_fee_period` (the longest collection cadence they'll accept). Those values are recorded on the `QuorumMember` struct (`deposits-protocol/src/types/core.rs:572`) and become part of the cosignable ledger state.

When the operator opens a deposit, the *strictest* member's minimums are the floor. The reference implementation computes this exactly that way (`deposits-core/tests/quorum_fee_limits_test.rs:79`):

```rust
fn strictest_quorum_limits(members: &[QuorumMember])
    -> (Option<u16>, Option<u64>, Option<u32>)
{
    let mut min_bps: Option<u16> = None;
    let mut min_fixed: Option<u64> = None;
    let mut max_period: Option<u32> = None;
    for m in members {
        if let Some(bps) = m.min_fee_bps {
            min_bps = Some(min_bps.map_or(bps, |cur| cur.max(bps)));
        }
        if let Some(fixed) = m.min_fee_fixed {
            min_fixed = Some(min_fixed.map_or(fixed, |cur| cur.max(fixed)));
        }
        if let Some(period) = m.max_fee_period {
            max_period = Some(max_period.map_or(period, |cur| cur.min(period)));
        }
    }
    (min_bps, min_fixed, max_period)
}
```

A member who declares `min_fee_bps = 50` is saying: "I will not co-sign deposits that earn less than 50 bps annualized, because the operator's projected revenue won't cover what they owe me as compensation." If any other member's number is higher, that one wins. A member that wants more frequent collection (smaller `max_fee_period`) similarly tightens the schedule.

The reason this matters has nothing to do with any single deposit and everything to do with **custody transfer**. Recall from [Chapter 7](07-quorum-and-collateral.md) and the fraud-proof pipeline that members can be slashed and may end up taking over the ledger after a recovery. When that happens, the new operator inherits every existing deposit and its existing fee schedule. If the deposits were opened at fees too low for the new operator to service profitably, the new operator's incentives flip — they're now custodying value at a loss and have economic reason to walk away or behave badly. The member fee floor is how members protect themselves from inheriting that scenario: by refusing to co-sign deposits that their own books wouldn't service profitably, they keep the ledger transferable.

This is the protocol enforcing operator profitability for the system's sake, not the operator's.

## Changing the fees: `FeeChange`

A wallet that accepted a fee schedule at deposit-open did so with the understanding that it would be relatively stable. But operator costs change — Bitcoin price fluctuates, collateral demand shifts, member compensation gets renegotiated — and operators need a way to update fees without forcing every depositor to close and reopen.

DEP-07 specifies the `FeeChange` operation (discriminator 22). The operator names a new `FeeStructure` and an `effective_block`, and three constraints govern the announcement:

1. **Minimum delay since opening.** `current_block >= opened_at_block + fee_change_after_blocks`. The deposit must have existed for at least this long before its first fee change.
2. **Sufficient notice.** `effective_block >= current_block + fee_change_notice_blocks`. The new fees can't take effect immediately; depositors get at least this many blocks' warning.
3. **Bounded magnitude.** Both `annualized_bps` and `annualized_msats` may move by no more than `fee_change_limit_bps` (basis points of the *current* value) per change. Default is 1000 bps = 10%.

These three parameters live on the `Deposit` itself (`deposits-protocol/src/types/core.rs:367`) and are negotiated at open time alongside the schedule. They are governance parameters: how aggressively the operator can adjust fees on this particular deposit. A wallet shopping for stability picks a deposit with strict (small) `fee_change_limit_bps`; an operator who wants flexibility pushes for laxer values; the open negotiation finds a meeting point.

Validation happens in `validate_deposit_fee_change` (`deposits-core/src/operation_validation.rs:649`):

```rust
pub fn validate_deposit_fee_change(
    ledger: &Ledger,
    deposit_id: &DepositId,
    new_fees: &FeeStructure,
    effective_block: u32,
    current_block: u32,
) -> ValidationResult
```

The function checks the after-blocks window, then the notice window, then computes the absolute change in `annualized_bps` and `annualized_msats` and rejects if it exceeds the limit. A `FeeChange` that fails any of these is non-conforming — the cosigners refuse, and if the operator somehow signed and broadcast it, fraud-proof verifiers will replay the chain, see the violation, and slash. (Chapter 11 covers the verifier flow.)

When a valid `FeeChange` lands, the new schedule does not take effect immediately. It is stored as `pending_fee_change: Option<(FeeStructure, u32)>` on the deposit. The schedule swaps in the next time `FeeCollect` runs at or after `effective_block` (`deposits-protocol/src/types/ledger_state.rs:447`):

```rust
LedgerOperation::FeeCollect { deposit_id, amount, block_height } => {
    if let Some(deposit) = next.deposits.get_mut(deposit_id) {
        if let Some((new_fees, effective)) = deposit.pending_fee_change.take() {
            if *block_height >= effective {
                deposit.fees = new_fees;
            } else {
                deposit.pending_fee_change = Some((new_fees, effective));
            }
        }
        deposit.balance = deposit.balance.saturating_sub(*amount);
        deposit.last_fee_assessment = *block_height;
        next.fees_accumulated = next.fees_accumulated.saturating_add(*amount);
    }
}
```

Two things to notice. First, `FeeChange` only stages; `FeeCollect` is what activates. So a depositor who's watching for fee changes doesn't have to chase pending state — the fee that matters is whatever `deposit.fees` looks like at the moment they make a transaction. Second, a subsequent `FeeChange` overwrites a still-pending one. There's no queue; only the most recent announcement matters.

Why this combination of limits? It's a defense against an operator's most obvious griefing strategy: announce extortionate fees with no warning, force depositors to either pay or exit immediately under unfavorable conditions. With `fee_change_limit_bps = 1000` and `fee_change_notice_blocks = 1008` (about a week), the worst the operator can do per change is +10%, and the depositor has a week to either accept it or move funds via `OnchainLock` exit or a courier-bridged transfer. To 100x the fees the operator would need 50+ separate `FeeChange` announcements, each forced by `fee_change_after_blocks` to be a minimum interval apart, with depositors watching every step. The mechanism doesn't make exploitation impossible — the operator can still slowly bleed depositors — but it makes it loud and slow enough that a wallet's automated monitoring will catch it.

## `FeeCollect`: assessing the rent

The companion operation is `FeeCollect` (discriminator 50). It's how the operator actually moves accrued custody fee from the deposit's `balance` into the ledger's `fees_accumulated`. The validator (`validate_fee_collect`, `operation_validation.rs:278`) checks:

- The deposit exists.
- The deposit has at least `amount` of available (un-locked) balance.
- `block_height >= last_fee_assessment + frequency_blocks`.

That last constraint is the rate limit: the operator can only collect on the schedule the deposit was opened with. Collect-too-early is non-conforming and the cosigners reject. Collect-too-late, on the other hand, is *not* non-conforming — DEP-11 explicitly classifies fee collection as advisory:

> Skipping or delaying collection is not non-conforming — it reduces operator revenue but does not affect depositor funds. Quorum members may decline to co-sign for operators who do not collect fees, as uncollected fees create accounting discrepancies.

The wallet has no enforceable obligation to a `FeeCollect` schedule. The operator does, in practice, because their members will gripe (and refuse renewals) if the books drift. But this is a member-vs-operator economic concern, not a fraud-proof one.

## Time obligations: the broader pattern

Fee changes are one instance of a broader pattern: certain operations are valid only after N blocks since some prior event. DEP-11 catalogs the instances. The vocabulary used throughout is:

- **Block height**, never wall-clock time.
- **Slashable** vs **advisory** — the former is provable as fraud and triggers the dispute pipeline; the latter is a degraded-service signal.

The slashable obligations span at least the following:

| Obligation | Trigger | Anchor | Window |
|---|---|---|---|
| On-chain credit | Operator signs past `deadline_block` without `OnchainCredit` | Cosigned funding offer | Set per-offer |
| Lightning credit | Preimage exists, no credit | The cosigned invoice | Until expiry |
| Transfer timeout | Operator signs past `timeout_height` with funds locked | `TransferLock` | Set per-lock, capped by `max_transfer_timeout_blocks` |
| Service response | Operator advances past `DeliveryEmbed.block_height + service_response_blocks` without processing | `DeliveryEmbed` (Chapter 15) | Default 72 (~12h) |
| Quorum rotation | Operator signs past `quorum_expiry` without new `QuorumBegin` | Quorum start | Set per-quorum |
| Dispute response | Member active past `evidence_block + dispute_response_blocks` without disputing | Fraud evidence | Default 144 (~1 day) |
| Collateral maintenance | UTXO reduced below `reserves + collateral` | Quorum activation | Continuous |

The advisory ones — fee-collection cadence, cosign latency, evidence retention — round out the set but don't trigger slashing.

The per-quorum timing parameters live on `QuorumAddMember`, recorded at join time so all parties agree on obligations from the start: `dispute_response_blocks`, `dispute_arm_blocks`, `service_response_blocks`, `max_transfer_timeout_blocks`. These are the same struct fields that carry `min_fee_bps` etc. — quorum members negotiate availability terms and economic terms in the same bundle, on the same wire.

## Why block-height instead of wall clock

A deposits ledger is hash-chained to Bitcoin block heights. Every `SignedLedgerUpdate` includes the `block_height` it was signed at. Why heights and not Unix timestamps?

Three reasons. First, **deterministic across nodes**: every node that's caught up to the same Bitcoin chain sees the same block height. Wall-clock timestamps depend on each peer's NTP sync and are easy to fudge. A signed update with an honest height that disagrees with chain reality is detectable (the cosigners refuse); a signed update with a forged timestamp two minutes off would pass naïve validation.

Second, **Bitcoin-native economics**. Fees in this protocol are denominated in satoshis and pegged to per-block production. A "weekly" notice in blocks is a stable unit of Bitcoin work; a "weekly" notice in seconds is a stable unit of Earth rotation, which is conceptually unrelated to anything else in the system.

Third, **reorg-safety is bounded**. A blockchain can rewind by N blocks in a reorg, but reorg probability falls off geometrically with N. This is the standard *confirmation depth* technique: any obligation that depends on an event in block X holds N blocks for `(X + N - chain_tip)` confirmations before treating it as final. The reference deployment uses 6 confirmations on mainnet for cosign-relevant on-chain events (see `default_quorum_begin_confs` in `deposits-core/src/quorum_policy.rs:26`), shorter on testnets. Wallets crediting on-chain deposits use longer windows still. Reorgs deeper than the chosen confirmation depth are vanishingly rare for any real deployment, and the protocol simply accepts them as out-of-scope (a 100-block reorg means Bitcoin itself has bigger problems).

The standard practice extends to fraud proofs: a fraud proof citing an event from N blocks ago must hold `dispute_response_blocks` (default 144) before the obligation lapses, leaving room for the cited block to re-org and the cited event to vanish. If it does, the proof is no longer valid; if it doesn't, the obligation fires.

## Defenses in depth

What stops an operator from doing something time-based that's premature?

- **Validation rejects.** `validate_deposit_fee_change`, `validate_fee_collect`, the lock-timeout checks in `validate_transfer_lock`, the `quorum_expiry` check on every commit — these all run on the operator's own daemon before a `Commit` even goes out. An honest operator's own software refuses to stage the operation.
- **Members refuse to co-sign.** The same validators run inside every quorum member's `checked_apply` path. An operator who patched their daemon to skip local validation still can't get majority cosignatures.
- **Fraud-proof verifiers reject.** If the operator somehow produced a majority cosig — by bribing or compromising members — the broadcast update is on Nostr forever, and any independent verifier replaying the chain catches the same violation. The fraud-proof pipeline (Chapter 11) treats it as evidence and slashes.

Three layers of defense for one rule. This is the layer model: members don't trust the operator, and verifiers don't trust the members. The protocol is intentionally redundant about predicates that have economic teeth.

## The fee/time interaction in one paragraph

Here is the picture all at once. A wallet opens a deposit at block B with a schedule S, governance parameters G (after, notice, limit-bps), and fees that meet the strictest member's floor F. The operator collects rent on cadence `S.frequency_blocks` via `FeeCollect`, accumulating into `fees_accumulated`. If the operator wants to raise rates, they wait `G.fee_change_after_blocks` past B, announce a `FeeChange` with effective block at least `G.fee_change_notice_blocks` in the future, and the new schedule is bounded to ±`G.fee_change_limit_bps` of the old. Members validate every step against the same rules. The new schedule activates the next `FeeCollect` after the effective block. If the operator does any of this wrong — collects too early, changes too aggressively, signs with a stale `block_height` — the violation is provable by anyone who can replay the chain.

## Where this leads

[Chapter 11](11-fraud-proofs.md) builds the fraud-proof system on top of this foundation. Almost every fraud-proof verifier in the codebase is, at heart, a comparison between two fee-or-time predicates: did the operator credit before the offer's `deadline_block`, did they sign past `quorum_expiry`, did they fail a transfer past `timeout_height`. The fee schedule and the time-obligation table are what those predicates evaluate against. With this chapter you have the predicate side; the next chapter is what the protocol does when a predicate is violated.
