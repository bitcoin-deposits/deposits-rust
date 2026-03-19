# DEP-07: Fee Schedules

## Abstract

This document specifies the fee structures for Bitcoin Deposits: periodic custody fees, per-transfer fees, fee negotiation at deposit opening, and the fee change mechanism with block notice and change limits.

## Status

Placeholder -- to be extracted from the reference implementation.

## Scope

### Periodic Custody Fees (FeeStructure)

- `annualized_fixed`: fixed fee per year (msats)
- `annualized_bps`: proportional fee rate (basis points per year)
- `frequency_blocks`: collection period (blocks)
- Collected via `FeeCollect` operation, pro-rated for elapsed blocks

### Per-Transfer Fees (TransferFeeSchedule)

- `fixed_sats`: fixed fee per transfer (sats)
- `rate_bps`: proportional fee per transfer (basis points)
- Fee = `fixed_sats + (amount * rate_bps / 10000)`

### Fee Negotiation

- Fee schedules are negotiated at `DepositOpen`
- Quorum members specify minimums via `QuorumAddMember` (see DEP-05)
- Deposits must meet the strictest quorum member's minimums

### Fee Changes

Parameters negotiated at deposit opening:

- `fee_change_after_blocks`: blocks after opening before any change
- `fee_change_notice_blocks`: blocks of notice before change takes effect
- `fee_change_limit_bps`: maximum change per adjustment (basis points of current fee)

A `FeeChange` (disc 22) announces new fees with an `effective_block`. Validation checks:

1. Current block >= `opened_at_block + fee_change_after_blocks`
2. `effective_block` >= current block + `fee_change_notice_blocks`
3. Change in `annualized_bps` and `annualized_fixed` within `fee_change_limit_bps` of current values

The change is stored as `pending_fee_change` and applied when `FeeCollect` runs at or after `effective_block`.

## Related DEPs

- [DEP-02](DEP-02.md): Ledger State Model (DepositOpen, FeeChange, FeeCollect operations)
- [DEP-05](DEP-05.md): Quorum and Collateral (fee limits negotiated by quorum members)
