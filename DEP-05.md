# DEP-05: Quorum and Collateral

## Abstract

This document specifies the quorum membership protocol and collateral mechanics. An operator puts up collateral on quorum member ledgers and, in exchange, those members co-sign the operator's ledger updates. The collateral secures the operator's obligations — if the operator misbehaves, members can confiscate the collateral held on their ledgers.

## Quorum Membership

### Joining

An operator requests another operator to join their quorum. The request includes:

- The member's pubkey and the member's ledger ID (where the operator will open collateral)
- The operator's collateral commitment (amount and lock duration on the member's ledger)
- Fee limits the member imposes (minimum fees the operator must charge)

If the member accepts, the operator appends `QuorumAddMember` (disc 43) to their own ledger, and the member appends `QuorumJoin` (disc 46) to their own ledger. This creates a two-sided auditable record.

### Member Terms

When joining, each member specifies:

- **min_fee_bps**: minimum annualized fee rate (basis points) the operator must charge
- **min_fee_fixed**: minimum annualized fixed fee (msats/year)
- **max_fee_period**: maximum fee collection period (blocks)
- **collateral_lock_amount**: minimum collateral the operator must maintain on the member's ledger (msats)
- **collateral_lock_until**: block height until which the operator's collateral must remain locked

The operator cannot open deposits with fees below the strictest member's minimums. This protects members from inheriting unprofitable obligations after a custody transfer.

- **max_descriptor_bytes**: maximum serialized descriptor size (bytes) the member will accept on deposits they may inherit after custody transfer

Members also specify timing parameters that govern protocol obligations (see DEP-11):

- **dispute_response_blocks**: blocks before a member must respond to embedded fraud evidence
- **dispute_arm_blocks**: blocks after `DisputeEnter` during which members must arm for the lottery
- **service_response_blocks**: blocks before an unprocessed signed request becomes provable censorship
- **max_transfer_timeout_blocks**: maximum `timeout_height` distance for `TransferLock`

The strictest (smallest) values across all members apply to the quorum. The operator cannot open deposits with descriptors exceeding the quorum's `max_descriptor_bytes` limit.

### QuorumBegin (disc 12)

Once members are added, the operator rotates reserves into a new Taproot multisig UTXO (see DEP-03). After `QuorumBegin`, co-signatures become required for all subsequent updates. `QuorumBegin` records the `quorum_expiry` (shortest collateral lock) and `total_collateral` (sum of all attestations).

### Removing Members

`QuorumRemoveMember` (disc 44) removes a member from the quorum. This requires a new `QuorumBegin` to update the multisig.

## Collateral

Collateral is the operator's own capital, deposited and locked on quorum member ledgers. It gives members skin in the game: if the operator misbehaves, the member can confiscate the collateral on their ledger.

### Locking

The operator:

1. Opens a deposit on the member's ledger with `is_collateral: true` (see DEP-08)
2. Funds it with their own capital via on-chain or lightning (see DEP-10)
3. Locks it with `CollateralLock` (disc 45), specifying amount, lock_until_block, and the operator being backed

The locked collateral cannot be withdrawn until the lock expires.

### Attestation

After the operator locks collateral on a member's ledger, the member returns a signed attestation confirming the lock. The operator then publishes a `CollateralAttestation` (disc 42) on their own ledger, wrapping the member's attestation. This proves to anyone reading the operator's ledger that collateral backing exists on the member's ledger.

The attestation includes: which member holds the collateral, which ledger it's on, the amount, the lock expiry, and the member's signature.

## Obligation Limits

A ledger's total obligations (sum of all deposit balances and locked amounts) must not exceed the least of:

1. The reserves amount (from LedgerOpen/QuorumBegin)
2. The sum of all attested collateral (`total_collateral` from QuorumBegin)
3. Twice the smallest `collateral_lock_amount` across all quorum members

This is enforced when creating new funding offers or invoices (see DEP-10). The `total_collateral` field on `QuorumBegin` gives wallets a single co-signed value to check against.

### Security Model

Consider a 3-member quorum where each member holds collateral C:

- Total collateral at risk: 3C (one deposit per member)
- Maximum obligations: 2C (from limit #3)
- Reserves UTXO: ≥ 2C (from limit #1)

A coordinated theft yields at most 2C but costs 3C in confiscated collateral — the attack costs 1.5× what it gains. In the non-colluding failure case (operator disappears), the reserves UTXO covers obligations at 1:1, and the quorum spends it to a new custodian via the lottery (see DEP-06).

### Multi-Ledger Collateral

The same collateral deposit on a member's ledger may back multiple ledgers of the same operator. Wallets should prefer operators with non-overlapping collateral sources, as shared collateral provides weaker per-ledger coverage. The mechanism for discovering and accounting for multi-ledger collateral reuse is an open design question.

## Co-Signer Obligations

Quorum members must maintain a full state replica of any ledger they co-sign for. Before co-signing an update, the member must verify:

1. The running total of obligations does not exceed the obligation limits above
2. The update conforms to protocol rules (valid fees, correct balances, authorized operations)
3. The hash chain is intact (previous_hash matches the last chain_hash)

Co-signing without state validation is non-conforming — a member who co-signs an update that violates obligation limits is complicit in the violation and may have their own collateral confiscated on other ledgers where they are operators.

### Membership Duration

Quorum membership duration is limited by `quorum_expiry` — the shortest member's `collateral_lock_until`. After this block, the operator's collateral may be withdrawn by the operator (lock expired), and the quorum must be refreshed via a new `QuorumBegin`.

### Confiscation

If the operator is proven non-conforming (see DEP-06), members may confiscate the operator's collateral held on their ledgers. This is the primary economic deterrent against operator misbehavior.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumAddMember, QuorumRemoveMember, QuorumJoin, QuorumBegin, CollateralAttestation, CollateralLock fields)
- [DEP-03](DEP-03.md): On-chain transactions (reserves rotation, tapscript multisig)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (quorum members initiate disputes, confiscation)
- [DEP-07](DEP-07.md): Fee schedules (fee limits negotiated by quorum members)
- [DEP-08](DEP-08.md): Deposits (collateral deposits)
- [DEP-10](DEP-10.md): Payment channels (obligation limits enforced at offer/invoice creation)
- [DEP-11](DEP-11.md): Time obligations (quorum rotation, collateral maintenance)
- [DEP-12](DEP-12.md): Certified delivery (service_response_blocks enforcement)
