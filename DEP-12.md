# DEP-12: Delivery Escalation

## Abstract

This document specifies how wallets escalate unprocessed requests through quorum members, producing causally anchored evidence of delivery. When an operator ignores a wallet's request, the wallet can pay a quorum member to embed the request hash in their ledger, starting the `service_response_blocks` clock and creating evidence usable in a censorship proof.

## Problem

A wallet publishes a signed request (Kind 20101) to an operator's relay. The operator ignores it. The wallet cannot prove delivery — ephemeral Nostr events have no durability guarantee, no delivery receipt, and no causal ordering. The operator's defense is "I never saw it."

## Escalation Protocol

### Step 1: Direct Request

The wallet publishes a signed request (Kind 20101) to the operator's advertised relay(s). This is the normal flow defined in DEP-04. Most requests are processed here.

### Step 2: Quorum Member Delivery

The wallet sends the signed request to one or more quorum members via the standard Kind 20101 request kind defined in DEP-04, addressed to the member's pubkey rather than the operator's. The request body includes:

- The original signed request payload (whatever the operator was supposed to process)
- The wallet's payment commitment for the embedding (per-vbyte price the member advertised)

The member processes the request by:

1. Validating the request signature (proves it came from the deposit's descriptor owner)
2. Validating the payment commitment (typically a `TransferLock` or off-chain settlement against the wallet's deposit on the member's ledger)
3. Appending a `DeliveryEmbed` (disc 80) to their own ledger with the request hash
4. Returning a Kind 20102 response confirming the embed event id and ledger sequence

The `DeliveryEmbed` is a co-signed ledger update on the member's chain — broadcast to relays as a normal Kind 9100 ledger update. At the next co-signature the member provides to the operator's ledger, the member's `member_ledger_hash` will reference a state that includes the embedded request hash. The operator, by co-signing, proves they have seen a state that contains the delivery.

**Implementation status.** `LedgerOperation::DeliveryEmbed` (disc 80) and the operator/member-side `recovery embed-hash` CLI are wired today. The wallet → member request channel via Kind 20101 is the natural extension of the existing wallet → operator request flow but isn't yet plumbed end-to-end in the wallet code.

### Step 3: Clock Starts

The `service_response_blocks` clock begins at the `block_height` of the `DeliveryEmbed` update on the member's ledger. If the operator's ledger advances past `embed_block_height + service_response_blocks` without a corresponding operation, the censorship proof is complete.

## DeliveryEmbed Operation (disc 80)

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | discriminant | 1 | 80 |
| 270 | request_hash | 32 | SHA256 of the wallet's signed request payload |
| 272 | target_ledger_id | 32 | Ledger ID where the request should be processed |
| 274 | target_operator | 33 | Operator pubkey of the target ledger |

The member's ledger records the embed; the member does not write to the operator's ledger. Causal entanglement occurs naturally through the co-signature protocol.

## Censorship Proof Construction

A censorship proof consists of:

1. **The signed request**: wallet's original request payload with descriptor witness
2. **The delivery embed**: the `DeliveryEmbed` update on the member's ledger, with its sequence number and block_height
3. **The causal link**: the co-signed update on the operator's ledger whose `member_ledger_hash` references a state at or after the delivery embed
4. **The deadline breach**: a co-signed update on the operator's ledger with `block_height >= embed_block_height + service_response_blocks` and no corresponding operation for the request

The proof demonstrates: the request exists and is authorized, a quorum member received and anchored it, the operator's chain causally proves awareness, and the operator chose not to act within the deadline.

## Pricing

Members set their own embedding prices, advertised in their Kind 39100 events or negotiated per-request. Pricing per vbyte of the embedded request is natural — the member is providing anchored storage on their ledger. The wallet shops across quorum members for the best rate.

## Incentives

The member's embedding fee is the small, guaranteed payoff. The large, contingent payoff is collateral confiscation: if the delivery reveals genuine censorship, the member can initiate a dispute and confiscate the operator's collateral on their ledger. Members do not need to evaluate whether the request is legitimate — they embed the hash, collect the fee, and monitor the outcome.

If no quorum member accepts the embedding, the wallet learns that the quorum is unanimously uncooperative — a strong signal to distribute funds elsewhere and publish the evidence to network health monitors.

## Public Record

The `DeliveryEmbed` ledger update is itself the durable public record. Once the member appends it to their ledger, the standard Kind 9100 broadcast and relay retention apply — anyone monitoring the member's ledger can observe the escalation. This obviates a separate standalone "escalation notice" event:

- The signed request hash is committed in the embed (with `request_hash`, `target_ledger_id`, `target_operator`)
- The embed is causally ordered on the member's chain (provable via the member's hash chain)
- Relays retain it as part of the member's ledger feed
- The operator's subsequent co-signature on the member's ledger advances `member_ledger_hash` past the embed, locking in causal awareness

For network health monitors and discovery markets, the embed is the canonical event to watch. No additional Nostr kind is needed.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DeliveryEmbed operation fields, causal ordering via member_ledger_hash)
- [DEP-04](DEP-04.md): Peer messaging (Kind 20101 wallet → operator AND wallet → member requests; DeliveryEmbed rides Kind 9100 as a normal ledger update)
- [DEP-05](DEP-05.md): Quorum and collateral (service_response_blocks parameter, collateral confiscation)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (censorship proof construction, dispute initiation)
- [DEP-08](DEP-08.md): Deposits (descriptor limits enforced at opening)
- [DEP-11](DEP-11.md): Time obligations (service_response_blocks deadline, provable censorship)
