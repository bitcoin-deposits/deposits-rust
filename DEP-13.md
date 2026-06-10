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

### Courier PTLC pattern

The HTLC pattern above leaks the payment hash on the relay: an observer who sees both legs can match the hashes and link them as the same in-flight payment, even without knowing the parties involved. The PTLC variant uses `pointlock(P)` (DEP-16) in place of `sha256(H)` and a blinding scalar to break the link.

Setup:

1. **Wallet** picks a base scalar `s` (32 random bytes) and computes `P = G·s`. `s` stays secret until the wallet (or the wallet-controlled receiver deposit) claims Leg 2.
2. **Wallet** sends `P` to the courier in the route request (see §"Route Request — PTLC variant" below).
3. **Courier** picks a blinding scalar `t` (32 random bytes), computes the **point** `T = G·t`, and returns `T` to the wallet in the route response. The courier keeps `t` secret — disclosing the scalar would let the wallet derive `s + t` from its own knowledge of `s` and front-run the courier's claim on Leg 1.
4. **Wallet** computes `P_b = P + T` locally and uses it to build the Leg 1 lock.

Locks:

- **Leg 1 (Sender → Courier)** uses `completion_script = "pointlock(P_b)"` — the courier completes it by revealing `s + t`.
- **Leg 2 (Courier → Receiver)** uses `completion_script = "pointlock(P)"` — the receiver completes it by revealing `s`.

Settlement:

1. **Receiver** reveals `s` on Leg 2, claiming the funds.
2. **Courier** observes `s`, computes `s + t` (mod n on secp256k1), reveals it on Leg 1, claiming its funds.

An observer on either relay sees two unrelated points (`P` and `P_b`) and two unrelated scalars (`s` and `s + t`). Without knowing `t`, they cannot conclude the legs belong to the same payment. The privacy property is the same one Lightning's PTLC migration provides.

**Capability requirement.** Courier-PTLC requires every hop's operator to advertise the `pointlock` capability (DEP-16 §capability). Wallets that need PTLC privacy MUST filter courier candidates by the capabilities of the operators on both legs; couriers SHOULD advertise both `htlc_routing` and `ptlc_routing` service tags (see §"Courier Advertisement") so wallets can pick. Operators that haven't enabled `pointlock` still serve HTLC hops; the privacy property is unavailable for those.

**Failure modes.** If the courier reveals `s + t` but Leg 2 never settles (receiver never reveals `s`), Leg 1 still settles correctly for the courier — the courier's claim is independent of Leg 2's outcome. If Leg 2 settles but Leg 1 times out, the courier learns `s` but loses their Leg 1 stake; standard HTLC timeout-vs-revelation logic applies with `timeout_height` from `TransferLock` (DEP-09).

## Courier Advertisement (Kind 39102)

Couriers advertise their services via NIP-33 replaceable events on the ledger relay.

**Kind**: 39102

**Tags**:

| Tag | Value | Description |
|---|---|---|
| `d` | courier pubkey (hex) | Stable identifier for NIP-33 replacement |
| `service` | `htlc_routing` | Hash-locked routing service (always present) |
| `service` | `ptlc_routing` | Point-locked routing service. Present when the courier's binary supports PTLC routing — a courier-side capability assertion independent of which operators it carries hops on. The wallet pre-flights per-hop operator support by checking each ledger's Kind 39100 `capabilities.obligations` for `pointlock` (DEP-04 §"Capabilities"); a route succeeds only when both the courier's `ptlc_routing` tag and both hop operators' `pointlock` capability are present. May appear alongside `htlc_routing` as a second `service` tag. |
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

**Content** (JSON, HTLC variant — default):

```json
{
  "source_ledger": "<64 hex>",
  "dest_ledger": "<64 hex>",
  "dest_deposit_id": "<32 hex>",
  "amount_msats": 1000000,
  "lock_type": "htlc",
  "hash": "<64 hex>"
}
```

`lock_type` defaults to `"htlc"` when absent. The wallet generates the preimage and its `sha256` hash before sending the route request; the hash will be used in both transfer locks' `completion_script`.

**Content** (JSON, PTLC variant):

```json
{
  "source_ledger": "<64 hex>",
  "dest_ledger": "<64 hex>",
  "dest_deposit_id": "<32 hex>",
  "amount_msats": 1000000,
  "lock_type": "ptlc",
  "point_p": "<66 hex>"
}
```

`point_p` is the sender's payment point `P = G·s`, serialized as a 33-byte compressed secp256k1 point (66 hex chars). The wallet keeps `s` secret. The courier MUST reject a PTLC request whose `point_p` does not deserialize as a valid compressed point on the curve, or whose source/destination ledger advertisements do not include the `pointlock` capability.

### Step 2: Courier Responds

The courier validates the request, stores the pending route keyed by hash, and responds with Kind 20102:

**Tags**:

| Tag | Value | Description |
|---|---|---|
| `e` | request event ID | Links response to request |

**Content** (JSON, HTLC variant):

```json
{
  "success": true,
  "result": {
    "courier_deposit_id": "<32 hex>",
    "lock_type": "htlc",
    "hash": "<64 hex>",
    "fee_msats": 4202,
    "forward_amount_msats": 995798
  }
}
```

**Content** (JSON, PTLC variant):

```json
{
  "success": true,
  "result": {
    "courier_deposit_id": "<32 hex>",
    "lock_type": "ptlc",
    "point_p": "<66 hex>",
    "blinding_point": "<66 hex>",
    "fee_msats": 4202,
    "forward_amount_msats": 995798
  }
}
```

Common fields:

- **courier_deposit_id**: the courier's deposit on the source ledger (wallet locks to this)
- **fee_msats**: total route fee (fee_in + fee_out)
- **forward_amount_msats**: amount the courier will lock on the destination ledger
- **lock_type**: echoed from the request

PTLC-only fields:

- **point_p**: the sender's `P` echoed back (lets the wallet detect server-side substitution before locking)
- **blinding_point**: `T = G·t` as a 33-byte compressed secp256k1 point (66 hex). The wallet computes `P_b = P + T` locally and uses `pointlock(P_b)` for the Leg 1 lock. The courier MUST never disclose the scalar `t` itself.

Pending routes expire after 10 minutes if no matching inbound lock arrives.

## Transfer Execution

### Step 3: Wallet Locks to Courier

The wallet initiates a `transfer_lock` (DEP-09) on the source ledger:

- **source_deposit_id**: wallet's deposit
- **destination_deposit_id**: courier's deposit (from route response)
- **amount**: the full transfer amount
- **completion_script**:
  - HTLC: `sha256(<hash>)` (the hash from step 1)
  - PTLC: `pointlock(<P_b>)` where `P_b = P + T`, computed locally by the wallet from the response's `blinding_point`
- **timeout_height**: current block + safety margin (e.g., 288 blocks)

### Step 4: Courier Forwards

The courier monitors Kind 9100 updates for TransferLock operations targeting its deposits (filtered by `#i` tag). When it detects an inbound lock:

1. Looks up the route in its pending routes (keyed by `hash` for HTLC, by `point_p` for PTLC) to find the destination
2. If no pending route exists, falls back to a default routing strategy (HTLC only — PTLC requires explicit pre-negotiation because of the blinding state)
3. For PTLC: verifies the inbound lock's `completion_script` is `pointlock(P_b)` where `P_b == P + T` for the route's stored `P` and `t`. Rejects the route on mismatch.
4. Initiates a `transfer_lock` on the destination ledger:
   - **source_deposit_id**: courier's deposit on destination ledger
   - **destination_deposit_id**: wallet's deposit on destination ledger (from pending route)
   - **amount**: `forward_amount_msats` (inbound amount minus route fee)
   - **completion_script**:
     - HTLC: `sha256(<hash>)` (same hash)
     - PTLC: `pointlock(<P>)` (the sender's unblinded point — receiver claims by revealing `s`)
   - **timeout_height**: inbound timeout minus `timeout_margin_blocks` (e.g., 144 blocks)

The timeout margin ensures the courier can always claim the inbound side after learning `s` (or the preimage) from the outbound side.

### Step 5: Wallet Completes

The wallet monitors Kind 9100 updates on the destination ledger (filtered by `#d` and `#t=70`) for a TransferLock targeting its deposit. When found, the wallet sends a `transfer_complete` (Kind 20101 to the destination operator) carrying:

- **transfer_id**: from the outbound TransferLock
- For HTLC: **preimage** (32-byte hex) — the preimage of the lock's `sha256(H)`
- For PTLC: **scalar** (32-byte hex) — `s`, the scalar satisfying the lock's `pointlock(P)` (i.e., `G·s == P`)

The wallet supplies whichever field matches the lock's `completion_script` obligation; sending both is a protocol error.

### Step 6: Courier Completes

The courier monitors Kind 9100 updates on its ledgers for TransferComplete operations (filtered by `#d` and `#t=71`). When it observes a release on Leg 2:

1. Matches the outbound transfer_id to an active route
2. Builds the inbound-side `transfer_complete` witness:
   - HTLC: reuses the observed `preimage` verbatim
   - PTLC: extracts the observed scalar `s` from the Leg 2 witness, computes `s' = (s + t) mod n` on secp256k1 (where `t` is the courier's stored blinding scalar for this route), and uses `s'` as the scalar witness
3. Sends `transfer_complete` on the inbound ledger

Both transfers are now settled. The wallet's funds moved from ledger A to ledger B; the courier earned the route fee. For PTLC, an observer correlating the two `completion_script` values (`pointlock(P)` on Leg 2 vs `pointlock(P + T)` on Leg 1) sees two unrelated curve points; correlating the two revealed scalars (`s` vs `s + t`) also sees two unrelated 32-byte values.

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

- **No counterparty risk**: the HTLC/PTLC pattern ensures atomicity. Either both transfers complete (witness revealed) or both time out. Neither party can steal funds. For PTLC, the courier MUST keep the blinding scalar `t` secret — disclosing it would let the wallet derive `s + t` from its own knowledge of `s` and front-run the courier on Leg 1.
- **Timeout ordering**: the courier MUST set outbound timeout earlier than inbound. Violating this allows the wallet to claim outbound funds while the inbound lock expires, draining the courier.
- **Pending route expiry**: routes expire after 10 minutes to prevent hash collision attacks where a stale pending route redirects a legitimate transfer.
- **Courier liveness**: if the courier goes offline after locking outbound funds, the wallet can still complete by revealing the preimage. The courier's inbound lock will time out and funds return to the wallet.

## Related DEPs

- [DEP-04](DEP-04.md): Peer messaging (Kind 20101/20102 request/response, Kind 39102 advertisement)
- [DEP-07](DEP-07.md): Fee schedules (operator transfer fees read from advertisements)
- [DEP-09](DEP-09.md): Transfers (TransferLock/TransferComplete mechanics, completion scripts)
- [DEP-11](DEP-11.md): Time obligations (timeout enforcement, transfer fail deadlines)
