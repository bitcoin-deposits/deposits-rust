# DEP-11: Time Obligations

## Abstract

This document describes the time-sensitive obligations of operators, quorum members, and wallets. Failure to meet these obligations constitutes non-conformance and may trigger disputes. All times are measured in block height against the base layer.

## Operator Obligations

### On-chain Offer Credit

When an operator creates a cosigned funding offer (see DEP-10), they commit to credit the deposit after a specified number of confirmations. The offer includes a `deadline_block`. The operator MUST append an `OnchainCredit` operation before the funding transaction reaches `required_confirmations` blocks of depth.

Failure to credit after sufficient confirmations while continuing to sign ledger updates is provable fraud (see DEP-06, uncredited on-chain payment). The wallet retains the cosigned offer as evidence.

### Lightning Invoice Credit

When an operator creates a cosigned invoice (see DEP-10), they commit to credit the deposit upon receiving the preimage. The operator MUST append `InvoiceCredit` promptly after their lightning node settles the payment.

Unlike on-chain, this is not autonomously provable — the wallet needs the preimage from the payer to construct a fraud proof (see DEP-06, uncredited lightning payment).

### Transfer Timeout

When a `TransferLock` is appended with a `timeout_height`, the operator MUST append `TransferFail` after the timeout block is reached if no `TransferComplete` has been provided. Funds locked beyond the timeout without resolution are non-conforming.

### Fee Collection

The operator MUST collect fees within a reasonable window of the `frequency_blocks` period defined in the deposit's FeeStructure (see DEP-07). Skipping fee collection is not directly non-conforming, but accumulated uncollected fees create accounting discrepancies that quorum members may flag.

### Quorum Rotation

The operator MUST initiate a new `QuorumBegin` before the current quorum's earliest member expiry (`collateral_lock_until`). Allowing the quorum to expire without rotation leaves the ledger without co-signing, which is non-conforming. An operator who continues to sign updates after quorum expiry is operating without the bilateral agreement the protocol requires.

Specifically: if `current_block >= min(member.collateral_lock_until)` for any active quorum member and no new `QuorumBegin` has been appended, the ledger is in a non-conforming state.

## Quorum Member Obligations

### Co-signing

Quorum members MUST respond to co-sign requests within a reasonable time (implementation-defined, typically seconds). Persistent failure to co-sign disrupts the operator and may be grounds for removal.

### Dispute Participation

When a quorum member receives a valid fraud proof (Kind 9101) or dispute notification (Kind 9103) for a ledger they are a member of, they MUST evaluate the evidence and, if valid, initiate a dispute within a bounded number of blocks.

Failure to act on valid evidence while continuing to operate their own ledger is itself provable fraud (see DEP-06, inactive quorum member). The evidence of inactivity is:
- The original fraud proof hash was embedded before block N
- The member's ledger has updates after block N + `required_response_blocks`
- No dispute was initiated

### Collateral Maintenance

Quorum members MUST maintain their collateral lock through the committed `collateral_lock_until` block. Withdrawing or reducing collateral before expiry while still listed as a quorum member is non-conforming. The operator may remove such a member and initiate a new `QuorumBegin`.

## Wallet Obligations

### Evidence Retention

Wallets MUST retain cosigned offers and invoices until the corresponding credit appears on the ledger or the deadline expires. Without this evidence, the wallet cannot prove fraud.

### Dispute Detection

Wallets SHOULD periodically verify that ledger updates carry valid co-signatures. When co-signatures are absent or invalid, the wallet SHOULD query the network for dispute events and replay ledger history to identify custody changes.

### Fund Distribution

Wallets SHOULD distribute funds across multiple operators with non-overlapping quorum members to reduce exposure to any single operator failure. A deposit is only as available as its operator.

## Timeline Summary

| Event | Deadline | Consequence of missing |
|---|---|---|
| On-chain credit | `confirmed_block + required_confirmations` | Provable fraud (autonomous) |
| Lightning credit | Promptly after preimage receipt | Provable fraud (with preimage) |
| Transfer timeout | `timeout_height` | Operator must append TransferFail |
| Quorum rotation | Before `min(collateral_lock_until)` | Non-conforming (expired quorum) |
| Dispute response | `evidence_block + required_response_blocks` | Provable inactivity |
| Collateral lock | Through `collateral_lock_until` | Non-conforming (early withdrawal) |

## Related DEPs

- [DEP-03](DEP-03.md): On-chain transactions (reserves rotation timing)
- [DEP-05](DEP-05.md): Quorum and collateral (membership duration, collateral locks)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (dispute initiation, inactive member proof)
- [DEP-07](DEP-07.md): Fee schedules (collection period)
- [DEP-09](DEP-09.md): Transfers (timeout mechanics)
- [DEP-10](DEP-10.md): Payment channels (offer deadlines, invoice credit timing)
