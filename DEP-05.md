# DEP-05: Quorum and Collateral

## Abstract

This document specifies the quorum membership protocol and collateral mechanics for Bitcoin Deposits. Operators form quorums with other operators who lock collateral on their ledgers. The quorum co-signs updates, enforces fee limits, and participates in recovery when operators misbehave.

## Status

Placeholder -- to be extracted from the reference implementation.

## Scope

### Quorum Membership

- Membership request: operator sends `partner_add` with collateral commitment and fee limit terms
- Member response: if terms align, member records `QuorumJoin` on their own ledger
- Operator records `QuorumAddMember` with the member's terms (fee limits, collateral commitment)
- Membership duration limited to the shortest member's `collateral_lock_until`
- Members must operate their own ledger with at least half the collateral

### Collateral

- Collateral kept as locked deposits on quorum member ledgers
- `CollateralLock` operation locks deposit balance with expiry
- `CollateralAttestation` records the lock on the operator's ledger
- Collateral may back multiple ledgers (capital efficiency)
- Wallets should prefer non-overlapping collateral sources

### Obligation Limits

- Total obligations <= reserves amount (from ReservesIncrease/Rotate)
- Total obligations <= 2x the smallest quorum member's `collateral_lock_amount`
- Enforced at funding offer and invoice creation time
- The stricter limit wins

### Fee Limits

- Members specify minimums: `min_fee_bps`, `min_fee_fixed`, `max_fee_period`
- Deposits must meet the strictest quorum member's minimums
- Protects members from inheriting unprofitable obligations after custody transfer

## Related DEPs

- [DEP-02](DEP-02.md): Ledger State Model (QuorumAddMember, QuorumJoin, CollateralAttestation operations)
- [DEP-03](DEP-03.md): On-Chain Transaction Formats (reserves multisig includes quorum members)
- [DEP-06](DEP-06.md): Fraud Proofs and Recovery (quorum members initiate disputes)
- [DEP-07](DEP-07.md): Fee Schedules (fee limits are quorum-negotiated)
