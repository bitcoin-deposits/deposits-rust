# DEP-13: Couriers

## Abstract

This document specifies the protocol for couriers — automated services that hold deposits on multiple ledgers and carry transfers between them. Couriers advertise their capacity and fees via Nostr, accept delivery requests from wallets, and execute cross-ledger HTLC transfers autonomously.

## Problem

DEP-09 transfers move funds between deposits on the same ledger. A wallet with a deposit on Alice's ledger cannot send to a deposit on Bob's ledger — there is no on-ledger mechanism for cross-operator movement. Withdrawing to on-chain and re-depositing is slow and expensive.

## Solution

A courier holds deposits on multiple ledgers. When a wallet wants to move funds from ledger A to ledger B, the courier acts as an intermediary:

1. The wallet locks funds to the courier's deposit on ledger A (with a hash lock)
2. The courier locks funds from its deposit on ledger B to the wallet's deposit on ledger B (with the same hash lock)
3. The wallet reveals the preimage on ledger B, claiming the funds
4. The courier observes the preimage and completes the transfer on ledger A, claiming its funds

This is a standard HTLC (Hash Time-Locked Contract) pattern. The courier earns a fee for providing liquidity; no trust is required beyond the timeout guarantees already enforced by operators (DEP-11).

## Courier Advertisement (Kind 39102)

Couriers advertise their services via NIP-33 replaceable events on the ledger relay.

**Kind**: 39102

**Tags**:

| Tag | Value | Description |
|---|---|---|
| `d` | courier pubkey (hex) | Stable identifier for NIP-33 replacement |
| `service` | `htlc_routing` | Service type |
| `n` | network name | `bitcoin`, `testnet`, `signet`, or `regtest` |

**Content** (JSON):

```json
{
  "courier_pubkey": "<hex>",
  "service": "htlc_routing",
  "network": "bitcoin",
  "ledgers": [
    {
      "ledger_id": "<64 hex>",
      "deposit_id": "<32 hex>",
      "balance_msats": 500000000,
      "fee_in_fixed_msats": 100,
      "fee_in_rate_bps": 10,
      "fee_out_fixed_msats": 102,
      "fee_out_rate_bps": 30
    }
  ]
}
```

Each entry in `ledgers` describes a deposit the courier holds and the directional fees for that ledger:

- **fee_in**: the cost for the courier to *receive* on this ledger (courier's margin)
- **fee_out**: the cost for the courier to *send* from this ledger (operator transfer fee + courier's margin)

### Route Cost Estimation

A wallet estimating the cost of a transfer from ledger A to ledger B through a courier computes:

    route_fee = fee_out(A) + fee_in(B)

where `fee_out(A)` is evaluated at the transfer amount and `fee_in(B)` is evaluated at the transfer amount:

    fee = fixed_msats + (amount_msats * rate_bps / 10000)

The sender pays `amount`; the recipient receives `amount - route_fee`. The courier keeps `route_fee - operator_transfer_fee(A)` as profit.

## Route Request Protocol

Before initiating a transfer, the wallet requests a route from the courier via Nostr. This registers the destination with the courier so it knows where to forward funds.

### Step 1: Wallet Sends Route Request

The wallet sends a Kind 20101 event addressed to the courier:

**Tags**:

| Tag | Value | Description |
|---|---|---|
| `p` | courier pubkey | Identifies the target courier |
| `action` | `request_route` | Request type |

**Content** (JSON):

```json
{
  "source_ledger": "<64 hex>",
  "dest_ledger": "<64 hex>",
  "dest_deposit_id": "<32 hex>",
  "amount_msats": 1000000,
  "hash": "<64 hex>"
}
```

The wallet generates the preimage and hash before sending the route request. The hash will be used in both transfer locks.

### Step 2: Courier Responds

The courier validates the request, stores the pending route keyed by hash, and responds with Kind 20102:

**Tags**:

| Tag | Value | Description |
|---|---|---|
| `e` | request event ID | Links response to request |

**Content** (JSON):

```json
{
  "success": true,
  "result": {
    "courier_deposit_id": "<32 hex>",
    "hash": "<64 hex>",
    "fee_msats": 4202,
    "forward_amount_msats": 995798
  }
}
```

- **courier_deposit_id**: the courier's deposit on the source ledger (wallet locks to this)
- **fee_msats**: total route fee (fee_in + fee_out)
- **forward_amount_msats**: amount the courier will lock on the destination ledger

Pending routes expire after 10 minutes if no matching inbound lock arrives.

## Transfer Execution

### Step 3: Wallet Locks to Courier

The wallet initiates a `transfer_lock` (DEP-09) on the source ledger:

- **source_deposit_id**: wallet's deposit
- **destination_deposit_id**: courier's deposit (from route response)
- **amount**: the full transfer amount
- **completion_script**: `sha256(<hash>)` (the hash from step 1)
- **timeout_height**: current block + safety margin (e.g., 288 blocks)

### Step 4: Courier Forwards

The courier monitors Kind 9100 updates for TransferLock operations targeting its deposits (filtered by `#i` tag). When it detects an inbound lock:

1. Looks up the hash in its pending routes to find the destination
2. If no pending route exists, falls back to a default routing strategy
3. Initiates a `transfer_lock` on the destination ledger:
   - **source_deposit_id**: courier's deposit on destination ledger
   - **destination_deposit_id**: wallet's deposit on destination ledger (from pending route)
   - **amount**: `forward_amount_msats` (inbound amount minus route fee)
   - **completion_script**: `sha256(<hash>)` (same hash)
   - **timeout_height**: inbound timeout minus `timeout_margin_blocks` (e.g., 144 blocks)

The timeout margin ensures the courier can always claim the inbound side after learning the preimage from the outbound side.

### Step 5: Wallet Completes

The wallet monitors Kind 9100 updates on the destination ledger (filtered by `#d` and `#t=70`) for a TransferLock targeting its deposit with the matching hash. When found, the wallet sends a `transfer_complete`:

- **transfer_id**: from the outbound TransferLock
- **preimage**: the original preimage

### Step 6: Courier Completes

The courier monitors Kind 9100 updates on its ledgers for TransferComplete operations (filtered by `#d` and `#t=71`). When it sees the preimage revealed:

1. Matches the outbound transfer_id to an active route
2. Sends `transfer_complete` on the inbound ledger with the same preimage

Both transfers are now settled. The wallet's funds moved from ledger A to ledger B; the courier earned the route fee.

## Timeout Safety

The courier sets its outbound timeout strictly earlier than the inbound timeout:

    outbound_timeout = inbound_timeout - timeout_margin_blocks

This guarantees that if the outbound times out (wallet never reveals preimage), the inbound will also time out — the courier does not lose funds. If the wallet reveals the preimage on the outbound side, the courier has `timeout_margin_blocks` to observe it and complete the inbound side.

A typical margin is 144 blocks (~1 day). The wallet should set its inbound timeout to at least `2 * timeout_margin_blocks` to give the courier room.

## Fee Model

Couriers set a base margin and compute per-ledger directional fees:

- **fee_in** = courier margin (receiving costs nothing; this is pure profit)
- **fee_out** = operator transfer fee + courier margin (courier pays the operator to send)

The operator transfer fee is read from the operator's Kind 39100 advertisement (`transfer_fee_fixed_msats` and `transfer_fee_rate_bps`).

Couriers may vary fees per ledger based on available liquidity, demand, or operator pricing. Higher fees on scarce liquidity naturally rebalance the courier's positions.

## Discovery

Wallets discover couriers by fetching Kind 39102 events from the ledger relay, filtered by network. The advertisement contains all information needed to estimate costs and choose a courier:

- Which ledgers the courier bridges
- Available balance per ledger
- Directional fees per ledger

Wallets can compare multiple couriers and select based on fee, liquidity, or coverage.

## Security Considerations

- **No counterparty risk**: the HTLC pattern ensures atomicity. Either both transfers complete (preimage revealed) or both time out. Neither party can steal funds.
- **Timeout ordering**: the courier MUST set outbound timeout earlier than inbound. Violating this allows the wallet to claim outbound funds while the inbound lock expires, draining the courier.
- **Pending route expiry**: routes expire after 10 minutes to prevent hash collision attacks where a stale pending route redirects a legitimate transfer.
- **Courier liveness**: if the courier goes offline after locking outbound funds, the wallet can still complete by revealing the preimage. The courier's inbound lock will time out and funds return to the wallet.

## Related DEPs

- [DEP-04](DEP-04.md): Peer messaging (Kind 20101/20102 request/response, Kind 39102 advertisement)
- [DEP-07](DEP-07.md): Fee schedules (operator transfer fees read from advertisements)
- [DEP-09](DEP-09.md): Transfers (TransferLock/TransferComplete mechanics, completion scripts)
- [DEP-11](DEP-11.md): Time obligations (timeout enforcement, transfer fail deadlines)
