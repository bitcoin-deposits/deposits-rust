# DEP-04: Peer Messaging

## Abstract

This document specifies the Nostr-based peer messaging protocol used by Bitcoin Deposits. All communication between wallets and operators, and between operators, uses Nostr events with specific Kind numbers, tags, and content formats.

## Status

Placeholder -- to be extracted from the reference implementation.

## Scope

### Event Kinds

| Kind | Name | Persistence | Description |
|---|---|---|---|
| 9100 | Ledger Update | Durable | Signed ledger update (base64 TLV) |
| 9101 | Fraud Proof | Durable | Fraud proof broadcast (JSON) |
| 9103 | Dispute | Durable | Custody dispute notification (JSON) |
| 9104 | Recovery Agreement | Durable | Quorum member recovery agreement (JSON) |
| 20101 | Request | Ephemeral | Wallet-to-operator request (JSON) |
| 20102 | Response | Ephemeral | Operator-to-wallet response (JSON) |
| 39100 | Advertisement | Replaceable | Operator terms (JSON, NIP-33) |
| 39101 | Price Oracle | Replaceable | BTC/USD price (JSON, NIP-33) |

### Topics

- Event tags (`d`, `seq`, `prev`, `hash`, `t`, `i`, `l`, `action`, `p`)
- Relay architecture (operator relays for ephemeral, ledger relay for durable)
- Request/response protocol (action names, parameter formats, timeout behavior)
- Advertisement format (fees, limits, headroom, relay URL)
- Co-signing request/response flow (cosign_update, cosign_offer, cosign_invoice)

## Related DEPs

- [DEP-02](DEP-02.md): Ledger State Model (defines the TLV content of Kind 9100)
- [DEP-06](DEP-06.md): Fraud Proofs and Recovery (defines Kind 9101 and 9103 content)

## References

- [NIP-01: Basic Protocol](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [NIP-33: Parameterized Replaceable Events](https://github.com/nostr-protocol/nips/blob/master/33.md)
