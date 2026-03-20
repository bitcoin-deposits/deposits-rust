# DEP-05: Quorum and Collateral

## Abstract

This document specifies the quorum membership protocol and collateral mechanics. Operators form quorums with other operators who lock collateral on their ledgers. The quorum co-signs updates, enforces fee limits, and participates in recovery when operators misbehave.

## Quorum Membership

### Joining

An operator requests another operator to join their quorum by sending a `partner_add` request (see DEP-04) with:

- The member's pubkey and collateral ledger ID
- Fee limits the member is imposing (minimum fees the operator must charge)
- Collateral commitment (amount and lock duration)

If the member accepts, the operator appends `QuorumAddMember` (disc 43) to their ledger, and the member appends `QuorumJoin` (disc 46) to their own ledger. This creates a two-sided auditable record.

### Member Terms

When joining, each member specifies:

- **min_fee_bps**: minimum annualized fee rate (basis points) the operator must charge
- **min_fee_fixed**: minimum annualized fixed fee (msats/year)
- **max_fee_period**: maximum fee collection period (blocks)
- **collateral_lock_amount**: minimum collateral the member commits to maintain (msats)
- **collateral_lock_until**: block height until which collateral remains locked

The operator cannot open deposits with fees below the strictest quorum member's minimums. This protects members from inheriting unprofitable obligations after a custody transfer.

### QuorumBegin (disc 12)

Once members are added, the operator rotates reserves into a new Taproot multisig UTXO (see DEP-03). After `QuorumBegin`, co-signatures become required for all subsequent updates.

### Removing Members

`QuorumRemoveMember` (disc 44) removes a member from the quorum. This requires a new `QuorumBegin` to update the multisig.

## Collateral

### Locking

Collateral is kept on quorum member ledgers as locked deposits. The operator:

1. Opens a deposit on the member's ledger with `is_collateral: true` (see DEP-08)
2. Funds it via on-chain or lightning (see DEP-10)
3. Locks it with `CollateralLock` (disc 45), specifying amount, lock_until_block, and the operator being backed

### Attestation

After locking, the member records a `CollateralAttestation` (disc 42) on the operator's ledger, proving the collateral exists. The attestation includes the collateral amount, lock expiry, and the member's signature.

### Multi-ledger Collateral

The same collateral deposit may back multiple ledgers of the same operator. Wallets should prefer operators with non-overlapping collateral sources, as shared collateral provides weaker coverage.

## Obligation Limits

A ledger's total obligations (sum of all deposit balances and locked amounts) must not exceed the lesser of:

1. The reserves amount (from LedgerOpen/QuorumBegin)
2. Twice the smallest quorum member's `collateral_lock_amount`

This is enforced when creating new funding offers or invoices (see DEP-10). The operator cannot create offers or invoices that would exceed either limit.

### Membership Duration

Quorum membership duration is limited to the shortest member's `collateral_lock_until`. After this block, the member's collateral may be withdrawn and the quorum must be refreshed.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumAddMember, QuorumRemoveMember, QuorumJoin, QuorumBegin, CollateralAttestation, CollateralLock fields)
- [DEP-03](DEP-03.md): On-chain transactions (reserves rotation, tapscript multisig)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (quorum members initiate disputes)
- [DEP-07](DEP-07.md): Fee schedules (fee limits negotiated by quorum members)
- [DEP-08](DEP-08.md): Deposits (collateral deposits)
- [DEP-10](DEP-10.md): Payment channels (obligation limits enforced at offer/invoice creation)
