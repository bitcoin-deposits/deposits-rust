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

### Fee on Failure

Lock-then-resolve operations (`TransferLock`/`Complete`/`Fail`, `InvoiceLock`/`Fulfill`/`Fail`, `OnchainLock`/`Fulfill`/`Fail`) charge a fee even when the resolution is a failure. Rationale: the operator did real work holding the lock and coordinating the attempt. On the failure path:

- The **proportional** portion of the fee is zero, since no `amount` was moved.
- The **fixed** portion (`fixed_msats` from the deposit's current `TransferFeeSchedule`) is charged to the deposit and credited to the operator's `fees_accumulated`.
- Any locked capacity is otherwise released. For `TransferFail` specifically, the source recovers `amount + proportional_portion` — only `fixed_msats` stays with the operator. For `InvoiceFail` and `OnchainFail`, the locked `amount` is released in full (those ops don't lock an operator fee upfront) and `fixed_msats` is debited from the deposit's balance.

Implementations MUST use saturating subtraction so that a deposit whose balance dipped below `fixed_msats` between lock and fail does not panic or underflow — in that edge case the operator collects only what the deposit can afford.

### Fee Accumulator

Every ledger carries a monotonically non-decreasing `fees_accumulated: u64` counter tracking the total msats of fee the operator has earned on that ledger. Contributions:

| Op | Amount added |
|---|---|
| `FeeCollect` | `amount` |
| `TransferComplete` | `pending.fee` (fixed + proportional) |
| `TransferFail` | `source.transfer_fees.fixed_msats` |
| `InvoiceFail` | `deposit.transfer_fees.fixed_msats` |
| `OnchainFail` | `deposit.transfer_fees.fixed_msats` |

`OnchainLock.fee_sats` is a **miner** fee and is NOT accumulated on success or failure. Successful `InvoiceFulfill` and `OnchainFulfill` do not currently contribute (no operator-fee model on those paths today).

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
