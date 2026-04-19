# DEP-11: Time Obligations

## Abstract

This document describes the time-sensitive obligations of operators, quorum members, and wallets. Obligations are either slashable (failure is provable and triggers penalties) or advisory (failure has natural consequences but is not directly punishable).

All times are measured in block height against the base layer.

## Operator Obligations

### On-chain Offer Credit
When an operator creates a cosigned funding offer (see DEP-10), they commit to credit the deposit. The offer includes a `deadline_block`. The operator must append an `OnchainCredit` before signing any update with a `block_height` exceeding `deadline_block`.

Signing an update past the deadline without crediting is provable fraud: the cosigned offer + the signed update with a later block_height constitute a complete fraud proof (see DEP-06).

### Lightning Invoice Credit
When an operator creates a cosigned invoice (see DEP-10), they commit to credit the deposit upon payment. If the payer provides the preimage to the wallet, and the operator has not credited the deposit, the wallet can construct a fraud proof.

Without the preimage, this obligation is not autonomously provable.

### Transfer Timeout
When a `TransferLock` is appended with a `timeout_height`, the operator must append `TransferFail` after the timeout block is reached if no `TransferComplete` has been provided. Signing updates past `timeout_height` while funds remain locked is provable non-conformance.

### Withdrawal and Transfer Processing
When a wallet's signed request is not processed by the operator, the wallet may escalate through certified delivery (see DEP-12). A quorum member embeds the request hash in their own ledger via `DeliveryEmbed`. The `service_response_blocks` clock starts at the embed's `block_height`. If the operator's ledger advances past the deadline without a corresponding operation, the combination constitutes a censorship proof.

`service_response_blocks` is a per-quorum parameter recorded in `QuorumAddMember`. The strictest value across all members applies.

Without this obligation, an operator could hold deposits hostage — refusing to process withdrawals without it being non-conforming. This is the provable service-level guarantee.

### Fee Collection
Fee collection is at the operator's discretion within the `frequency_blocks` period. Skipping or delaying collection is not non-conforming — it reduces operator revenue but does not affect depositor funds. Quorum members may decline to co-sign for operators who do not collect fees, as uncollected fees create accounting discrepancies.

### Quorum Rotation
The operator must append a new `QuorumBegin` before `quorum_expiry`. Signing updates after `quorum_expiry` without a new quorum is non-conforming — the operator is operating without the bilateral agreement the protocol requires. This is provable: any co-signed update with `block_height >= quorum_expiry` on a ledger without a subsequent `QuorumBegin` constitutes evidence.

## Quorum Member Obligations

### Co-signing
Co-signing timeliness is not protocol-enforced. A slow or unresponsive member will not be selected for the next quorum. The degraded spending path in the reserves tapscript (see DEP-03) allows the remaining members to rotate without the missing member.

### Dispute Participation
When valid fraud evidence is embedded in the causal chain and a quorum member's ledger has updates after the evidence block, the member must initiate a dispute. Failure to act while remaining active is provable: the fraud proof hash was embedded at block N, the member's ledger has updates after block N + `dispute_response_blocks`, and no dispute was initiated.

`dispute_response_blocks` is a per-quorum parameter recorded in `QuorumAddMember`, so all parties agree on the obligation at join time. Shorter values increase responsiveness requirements; longer values are more forgiving but delay recovery.

### Collateral Maintenance
The collateral portion of the operator's UTXO must be preserved through `quorum_expiry`. Co-signers MUST reject any operation that would reduce the UTXO value below `reserves_amount_msats + collateral_amount_msats`. If the operator spends the UTXO outside the quorum's control (e.g., via a tiered timeout path) before quorum expiry, this is provable non-conformance.

## Wallet Obligations

### Evidence Retention
Wallets should retain cosigned offers and invoices until the corresponding credit appears or the deadline expires. This is not a protocol obligation — it is in the wallet's self-interest. Without evidence, the wallet cannot prove fraud.

### Dispute Detection
Wallets should periodically verify co-signatures on ledger updates. When co-signatures are absent or invalid, the wallet should query for dispute events and replay history to identify custody changes.

### Fund Distribution
Wallets should distribute funds across operators with non-overlapping quorum members. A deposit is only as available as its operator.

## Timeline Summary

| Event | Deadline | Provable? |
|---|---|---|
| On-chain credit | Operator signs past `deadline_block` without credit | Yes (autonomous) |
| Lightning credit | Preimage exists, no credit | Yes (with preimage) |
| Transfer timeout | Operator signs past `timeout_height` with funds locked | Yes |
| Withdrawal/transfer processing | Operator signs past `DeliveryEmbed block_height + service_response_blocks` without processing embedded request | Yes |
| Quorum rotation | Operator signs past `quorum_expiry` without new quorum | Yes |
| Dispute response | Member active after `evidence_block + dispute_response_blocks` | Yes |
| Collateral maintenance | UTXO reduced below reserves + collateral | Yes |
| Fee collection | Within `frequency_blocks` | No (advisory) |
| Co-sign response | Timely | No (advisory) |
| Evidence retention | Until credit or expiry | No (self-interest) |

## Per-Quorum Parameters

The following timing parameters are recorded in `QuorumAddMember` so that all parties agree on obligations at join time:

| Parameter | Description | Suggested Default |
|---|---|---|
| `dispute_response_blocks` | Blocks before a member must respond to embedded fraud evidence | 144 (~1 day) |
| `dispute_arm_blocks` | Blocks after `DisputeEnter` during which members must arm | 144 (~1 day) |
| `service_response_blocks` | Blocks before an unprocessed signed request becomes provable censorship | 72 (~12 hours) |
| `max_transfer_timeout_blocks` | Maximum `timeout_height` distance for `TransferLock` | 1008 (~1 week) |

## Related DEPs

- [DEP-03](DEP-03.md): On-chain transactions (tapscript tiers, degraded quorum path)
- [DEP-05](DEP-05.md): Quorum and collateral (membership duration, collateral locks)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (dispute initiation, inactive member proof)
- [DEP-07](DEP-07.md): Fee schedules (collection period)
- [DEP-09](DEP-09.md): Transfers (timeout mechanics)
- [DEP-10](DEP-10.md): Payment channels (offer deadlines, invoice credit)
- [DEP-12](DEP-12.md): Certified delivery (escalation protocol, DeliveryEmbed, censorship proof construction)
- [DEP-13](DEP-13.md): Couriers (timeout margin safety for cross-ledger HTLC routing)
