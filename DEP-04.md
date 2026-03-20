# DEP-04: Peer Messaging

## Abstract

This document specifies the Nostr-based peer messaging protocol. All communication between wallets and operators, and between operators, uses Nostr events with specific Kind numbers, tags, and content formats.

## Relay Architecture

The protocol uses two types of relays:

- **Operator relays**: handle ephemeral request/response traffic. Each operator monitors one or more relays for incoming requests.
- **Ledger relay**: stores durable events (ledger updates, disputes, fraud proofs). Any relay that retains Kind 9100 events can serve as a ledger relay.

Wallets connect to both: operator relays for requests, ledger relays for reading history and advertisements.

## Event Kinds

| Kind | Name | Persistence | Description |
|---|---|---|---|
| 9100 | Ledger Update | Durable | Signed ledger update (base64 TLV, see DEP-02) |
| 9101 | Fraud Proof | Durable | Fraud proof broadcast (JSON, see DEP-06) |
| 9103 | Dispute | Durable | Custody dispute notification (JSON) |
| 9104 | Recovery Agreement | Durable | Quorum member recovery agreement (JSON) |
| 20101 | Request | Ephemeral | Wallet-to-operator request (JSON) |
| 20102 | Response | Ephemeral | Operator-to-wallet response (JSON) |
| 39100 | Advertisement | Replaceable | Operator terms (JSON, NIP-33) |
| 39101 | Price Oracle | Replaceable | BTC/USD price (JSON, NIP-33) |

## Event Tags

| Tag | Usage | Description |
|---|---|---|
| `d` | Kind 9100, 39100 | Ledger ID (64 hex chars). For Kind 39100, enables NIP-33 replacement. |
| `seq` | Kind 9100 | Sequence number (for relay-side ordering) |
| `prev` | Kind 9100 | Previous chain hash (hex) |
| `hash` | Kind 9100 | Current hash (hex) |
| `t` | Kind 9100 | Operation discriminant number (for relay-side filtering) |
| `i` | Kind 9100 | Affected deposit IDs (for per-deposit filtering) |
| `l` | Kind 20101, 20102 | Ledger ID (for relay-side request routing) |
| `action` | Kind 20101 | Request action name |
| `p` | Kind 9101 | Accused operator pubkey |

## Request/Response Protocol

Wallets send ephemeral Kind 20101 events to operator relays. The content is JSON with an `action` field and operation-specific parameters. The operator processes the request and responds with a Kind 20102 event tagged with the request's event ID.

### Request Actions

| Action | Description | See |
|---|---|---|
| deposit_open | Open a new deposit | DEP-08 |
| make_offer | Create on-chain funding offer | DEP-10 |
| make_invoice | Create lightning invoice | DEP-10 |
| pay_invoice | Pay lightning invoice from deposit | DEP-10 |
| withdraw | On-chain withdrawal | DEP-10 |
| transfer_lock | Lock funds for transfer | DEP-09 |
| transfer_complete | Complete a transfer | DEP-09 |
| balance_query | Query deposit balance | DEP-08 |
| cosign_update | Request co-signature on update | DEP-02 |
| cosign_offer | Request co-signature on offer | DEP-10 |
| cosign_invoice | Request co-signature on invoice | DEP-10 |
| partner_add | Add quorum member | DEP-05 |
| partner_join | Record quorum join | DEP-05 |
| collateral_lock | Lock collateral | DEP-05 |
| collateral_record | Record collateral attestation | DEP-05 |

### Response Format

```json
{
  "success": true,
  "result": { ... },
  "error": null
}
```

## Advertisements (Kind 39100)

Operators publish NIP-33 replaceable events advertising their terms. The `d` tag is the ledger_id, ensuring only the latest advertisement per ledger is retained. Content includes:

- Operator name and pubkey
- Reserves amount, obligations, available headroom
- Fee schedules (periodic and transfer)
- Deposit limits (min/max)
- Relay URL
- Collateral enforcement block

Wallets discover operators by fetching Kind 39100 events from ledger relays.

## Offline Operation

Wallets need no persistent connections. They can go offline indefinitely and catch up by fetching Kind 9100 events from any relay that has them. The hash chain provides integrity verification — a wallet replays events and validates the chain regardless of when they were fetched.

## Related DEPs

- [DEP-02](DEP-02.md): Ledger update wire format (Kind 9100 content)
- [DEP-06](DEP-06.md): Fraud proof broadcast format (Kind 9101 content)

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) -- Nostr event structure
- [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md) -- Parameterized replaceable events
