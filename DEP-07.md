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

All fee arithmetic uses integer division with floor rounding. The operator appends `FeeCollect` (disc 50) with the computed fee, which is deducted from the deposit's balance.

## Per-Transfer Fees (TransferFeeSchedule)

Each transfer out of a deposit incurs a fee:

- **fixed_msats**: fixed fee per transfer (msats)
- **rate_bps**: proportional fee (basis points of the transfer amount)

Fee calculation:

    fee = fixed_msats + (amount_msats * rate_bps / 10000)

The sender must provide the exact expected fee in the `TransferLock` request. The operator rejects mismatches.

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
