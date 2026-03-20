# DEP-12: Delivery Escalation

## Abstract

This document specifies how wallets escalate unprocessed requests through quorum members, producing causally anchored evidence of delivery. When an operator ignores a wallet's request, the wallet can pay a quorum member to embed the request hash in their ledger, starting the `service_response_blocks` clock and creating evidence usable in a censorship proof.

## Problem

A wallet publishes a signed request (Kind 20101) to an operator's relay. The operator ignores it. The wallet cannot prove delivery — ephemeral Nostr events have no durability guarantee, no delivery receipt, and no causal ordering. The operator's defense is "I never saw it."

## Escalation Protocol

### Step 1: Direct Request

The wallet publishes a signed request (Kind 20101) to the operator's advertised relay(s). This is the normal flow defined in DEP-04. Most requests are processed here.

### Step 2: Durable Publication

If the operator does not respond within a wallet-chosen patience window, the wallet re-publishes the request as a durable Nostr event:

- **Kind 9105**: Delivery Escalation (durable)
- **Content**: the original signed request payload
- **Tags**:
  - `d`: deposit_id (hex)
  - `l`: ledger_id (hex)
  - `p`: operator pubkey
  - `action`: the request action (e.g., `withdraw`, `transfer_lock`)

This event is retained by relays and serves as a public record that the request was made. It is not causally ordered — Nostr event timestamps are not anchored in any chain and cannot be used as proof of timing.

### Step 3: Quorum Member Delivery

The wallet sends the signed request to one or more quorum members, requesting paid embedding. The member:

1. Validates the request signature (proves it came from the deposit's descriptor owner)
2. Appends a `DeliveryEmbed` (disc 80) to their own ledger with the request hash
3. Charges the wallet for the embedding (priced per vbyte at the member's discretion)

The `DeliveryEmbed` is a co-signed ledger update on the member's chain. At the next co-signature the member provides to the operator's ledger, the member's `member_ledger_hash` will reference a state that includes the embedded request hash. The operator, by co-signing, proves they have seen a state that contains the delivery.

### Step 4: Clock Starts

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

## Relay Integration

Kind 9105 events are durable and retained by relays. They serve as a public record but are not part of the censorship proof's evidentiary chain — the causal proof comes entirely from ledger updates. The durable event provides:

- A public signal that the wallet is escalating (reputation pressure on the operator)
- A record for network health monitors and discovery markets
- A fallback if the wallet needs to re-request embedding from different members

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DeliveryEmbed operation fields, causal ordering via member_ledger_hash)
- [DEP-04](DEP-04.md): Peer messaging (Kind 20101 requests, Kind 9105 durable escalation)
- [DEP-05](DEP-05.md): Quorum and collateral (service_response_blocks parameter, collateral confiscation)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (censorship proof construction, dispute initiation)
- [DEP-08](DEP-08.md): Deposits (descriptor limits enforced at opening)
- [DEP-11](DEP-11.md): Time obligations (service_response_blocks deadline, provable censorship)
