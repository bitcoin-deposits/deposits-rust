# DEP-07: Fee Schedules

## Abstract

This document specifies the fee structures for Bitcoin Deposits: periodic custody fees, per-transfer fees, fee negotiation at deposit opening, and the fee change mechanism with block notice and change limits.

## Periodic Custody Fees (FeeStructure)

Custody fees are charged periodically against deposit balances:

- **annualized_msats**: fixed fee per year (msats), pro-rated for elapsed blocks
- **annualized_bps**: proportional fee rate (basis points per year), applied to the deposit balance
- **frequency_blocks**: collection period (blocks) -- how often `FeeCollect` is appended

Fee calculation for a collection period:

    fixed_portion = annualized_msats * blocks_elapsed / 52560
    proportional_portion = balance * annualized_bps * blocks_elapsed / (52560 * 10000)
    total_fee = fixed_portion + proportional_portion

All fee arithmetic uses integer division with floor rounding. Implementations MUST compute the multiplicative chain in at least u128 (or equivalent wide integer) before dividing — with realistic whale balances (~10¹⁶ msats), the product `balance * annualized_bps * blocks_elapsed` exceeds 2⁶⁴ long before the divisor rescues it, and silent u64 wrap would let the operator collect an arbitrary fraction of the intended fee. The final quotient fits in u64 for any sane input; implementations SHOULD saturate the downcast rather than wrap.

The operator appends `FeeCollect` (disc 50) with the computed fee, which is deducted from the deposit's balance and added to the ledger's `fees_accumulated` counter (see below).

## Per-Transfer Fees (TransferFeeSchedule)

Each transfer out of a deposit incurs a fee:

- **fixed_msats**: fixed fee per transfer (msats)
- **rate_bps**: proportional fee (basis points of the transfer amount)

Fee calculation:

    fee = fixed_msats + (amount_msats * rate_bps / 10000)

The same wide-integer requirement applies: `amount_msats * rate_bps` can overflow u64 for large amounts; implementations MUST widen to u128 and saturate the downcast.

The sender must provide the exact expected fee in the `TransferLock` request. The operator rejects mismatches.

### Why two components, not bps-only

External reviewers periodically propose collapsing fees to basis-points-only on the grounds that a flat per-op fee "taxes the behaviors agent commerce runs on." That framing is wrong, and the protocol explicitly rejects it.

Per-operation cost is real and *not* amount-proportional. Each ledger update costs the operator and its quorum:

- a cosignature round-trip (one network RTT per cosigner, signature CPU)
- validation work (decode, replay against state, conformance check)
- storage (the signed update lives forever on the operator's relay and propagates to peers)
- bandwidth (gossip to the durable relay, the messaging relay, and any subscribed wallets)

A 1-sat micropayment imposes the same per-op cost on the operator as a 1-BTC settlement; only the *risk* component scales with amount. Bps-only fees would force the operator to subsidize every small operation out of large-operation revenue — a model that's unstable under volume mix shifts and creates an obvious griefing surface (flood the operator with sub-dust transfers; the operator either rejects them or runs at a loss).

The right shape for both `FeeStructure` and `TransferFeeSchedule` is:

- **`fixed_msats` covers the per-op cost floor.** Operators should set it as low as their actual operational cost permits — measured in msats, comfortably under common micropayment values. A reasonable target is "the operator's marginal cost per operation, plus a small margin," not "what the market will bear." Wallets should distrust operators whose fixed components are large relative to their bps components.
- **`*_bps` covers the value-proportional risk-and-capital cost** — the operator's exposure scales with the amount under management or in flight, and bps captures that cleanly.

Both halves serve a structural purpose. Dropping the fixed component would require either subsidizing micropayments (operator unstable) or refusing them (defeats the use case). Keep both, keep `fixed_msats` low.

### Bridge transfers

Lightning bridge ops (DEP-10 §Lightning) use the same `TransferFeeSchedule` as any other transfer — a bridge's `TransferLock` pays the standard `fixed_msats + rate_bps` fee to `fees_accumulated` like every other lock, regardless of which deposit holder is acting as the bridge. The bridge's own service fee (its margin for taking on Lightning routing risk) is captured externally via the difference between the BOLT-11 amount and the on-ledger transfer amount — it's market-priced, set by the bridge competitively, and never touches the protocol fee surface. This DEP says nothing about how bridges price their service; bridge advertisements (DEP-04) are the relevant venue. The protocol just ensures that whoever cosigns the bridge's `TransferLock` is paid the standard transfer-fee compensation.

## Fee on Failure

Lock-then-resolve operations (`TransferLock`/`Complete`/`Fail`, `InvoiceLock`/`Fulfill`/`Fail`, `OnchainLock`/`Fulfill`/`Fail`) charge a fee even when the resolution is a failure. Rationale: the operator did real work holding the lock and coordinating the attempt. On the failure path:

- The **proportional** portion of the fee is zero, since no `amount` was moved.
- The **fixed** portion (`fixed_msats` from the deposit's current `TransferFeeSchedule`) is charged to the deposit and credited to the operator's `fees_accumulated`.
- Any locked capacity is otherwise released. For `TransferFail` specifically, the source recovers `amount + proportional_portion` — only `fixed_msats` stays with the operator. For `InvoiceFail` and `OnchainFail`, the locked `amount` is released in full (those ops don't lock an operator fee upfront) and `fixed_msats` is debited from the deposit's balance.

Implementations MUST use saturating subtraction so that a deposit whose balance dipped below `fixed_msats` between lock and fail does not panic or underflow — in that edge case the operator collects only what the deposit can afford.

## Fee Accumulator

Every ledger carries a monotonically non-decreasing `fees_accumulated: u64` counter tracking the total msats of fee the operator has earned on that ledger. Contributions:

| Op | Amount added |
|---|---|
| `FeeCollect` | `amount` |
| `TransferComplete` | `pending.fee` (fixed + proportional; covers intra-ledger transfers AND bridge `TransferLock` ops — bridges pay the standard `TransferFeeSchedule` like any other transfer) |
| `TransferFail` | `source.transfer_fees.fixed_msats` |
| `InvoiceFail` | `deposit.transfer_fees.fixed_msats` |
| `OnchainFail` | `deposit.transfer_fees.fixed_msats` |

`OnchainLock.fee_sats` is a **miner** fee and is NOT accumulated on success or failure. Successful `InvoiceFulfill` and `OnchainFulfill` do not contribute (no operator-fee model on those paths today — `InvoiceLock`/`InvoiceFulfill` is the legacy operator-runs-the-LN-node pay path, kept around for back-compat; the modern bridge-mediated pay flow uses `TransferLock`/`TransferComplete` whose fee is captured under `TransferComplete` above).

The legacy `InvoiceCredit` op (deterrence-mode receive — DEP-10 §"Offline receive") also doesn't contribute to `fees_accumulated`, since the operator's fee on that path is collected entirely outside the ledger via the spread between LN routing/margin and what they choose to credit. Operators offering this path SHOULD price it conservatively given the lack of cosigner-enforced fee transparency.

`fees_accumulated` is serde-defaulted so pre-accumulator ledgers load with 0, and it is the substrate a future payout operation will debit against when distributing quorum-member compensation (see DEP-05).

## Fee Negotiation

Fee schedules are negotiated at deposit opening (`DepositOpen`). The operator's advertisement (Kind 39100) publishes their minimum fees. The wallet proposes fees in the open request; the operator validates they meet the minimums.

Quorum members also set fee minimums at join time (see DEP-05). The operator cannot open deposits with fees below the strictest quorum member's minimums.

## Fee Changes

Fee parameters negotiated at deposit opening:

- **fee_change_after_blocks**: blocks after opening before any change is allowed
- **fee_change_notice_blocks**: blocks of notice before a change takes effect
- **fee_change_limit_bps**: maximum change per adjustment (basis points of current fee, e.g. 1000 = 10%)

### FeeChange (disc 22)

The operator announces new fees with an `effective_block`:

1. `current_block >= opened_at_block + fee_change_after_blocks` -- enough time since opening
2. `effective_block >= current_block + fee_change_notice_blocks` -- sufficient notice
3. Change in `annualized_bps` and `annualized_msats` must be within `fee_change_limit_bps` of current values

The change is stored as `pending_fee_change` on the deposit. When `FeeCollect` runs at or after `effective_block`, the new fees take effect.

A subsequent `FeeChange` replaces any pending change.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (FeeStructure, TransferFeeSchedule nested TLV, FeeChange/FeeCollect fields)
- [DEP-05](DEP-05.md): Quorum and collateral (fee limits negotiated by quorum members)
- [DEP-08](DEP-08.md): Deposits (fee schedule established at opening)
- [DEP-09](DEP-09.md): Transfers (transfer fee validation)
