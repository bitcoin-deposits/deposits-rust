# Cosign Data Flow Architecture

## Overview

Each deposits-bdk node is both an **operator** (manages its own ledger) and a **quorum member** (co-signs updates on other operators' ledgers). The co-signature flow is the critical hot path: every transfer requires a co-sign round-trip through Nostr.

## Event Kinds

| Kind | Constant | Purpose | Delivery |
|------|----------|---------|----------|
| 9100 | `KIND_LEDGER_UPDATE` | Signed ledger state changes | `send_event` (wait for relay OK) |
| 9101 | `KIND_LEDGER_REQUEST` | RPC: transfer_lock, cosign_update, etc. | `send_event_nowait` (fire-and-forget) |
| 9102 | `KIND_LEDGER_RESPONSE` | RPC response to a request | `send_event_nowait` (fire-and-forget) |
| 9103 | `KIND_LEDGER_DISPUTE` | Dispute announcements | `send_event` |

## Internal Channels

All five channels are **unbounded mpsc** (no backpressure, no drops):

```
                       broadcast::Receiver (buffer=4096)
                     (from nostr-sdk relay pool background task)
                                    |
                          handle_notification()
                                    |
              +----------+----------+----------+----------+
              |          |          |          |          |
            Kind 4    Kind 9100  Kind 9101  Kind 9102  Kind 9103
              |          |          |          |          |
              v          v          v          v          v
          inbound_tx  ledger_tx  request_tx response_tx dispute_tx
              |          |          |          |          |
              v          v          v          v          v
          inbound_rx  ledger_rx  request_rx response_rx dispute_rx
```

## The Run Loop (`Node::run()`, node.rs:1006)

Single-threaded async loop. Each iteration:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. PERIODIC TASKS (every 5s fast / 60s normal)              │
│    sync_wallet, auto_complete_deposits, auto_collect_fees,  │
│    auto_timeout_transfers, etc.                             │
│    ⚠️ sync_wallet calls electrs — can take 100ms-2s         │
├─────────────────────────────────────────────────────────────┤
│ 2. RELOAD CYCLE (every 2s fast / 5s normal)                 │
│    discover_new_ledgers, subscribe, background gap-fill     │
│    ⚠️ auto_import_joined_ledgers fetches from relay          │
├─────────────────────────────────────────────────────────────┤
│ 3. POLLING FALLBACK (every 5s fast / 30s normal)            │
│    fetch_recent_requests(7s lookback)                       │
│    ⚠️ relay fetch with 5s timeout                            │
│    → handle_ledger_request() for each (SEQUENTIAL)          │
├─────────────────────────────────────────────────────────────┤
│ 4. PROCESS_EVENTS (100ms timeout)                           │
│    Drain broadcast receiver → route to mpsc channels        │
├─────────────────────────────────────────────────────────────┤
│ 5. DRAIN CHANNELS (order matters!)                          │
│    a. P2P inbound      (try_recv)                           │
│    b. Requests          (try_recv → handle_ledger_request)  │
│         ⚠️ SEQUENTIAL + ASYNC: each request awaited         │
│         ⚠️ transfer_lock → sign_and_broadcast → 9s worst    │
│    c. Disputes          (try_recv)                          │
│    d. Responses         (try_recv)                          │
│    e. Ledger updates    (try_recv → handle_ledger_update)   │
│    f. Outbound P2P      (try_recv)                          │
└─────────────────────────────────────────────────────────────┘
```

**Critical: requests are drained BEFORE updates (step 5b before 5e).**

## The Co-Sign Round Trip

### Operator Side (transfer_lock → cosign → broadcast)

```
process_transfer_lock_request()
  │
  ├─ Append TransferLock operation to ledger (seq N)
  │
  └─ sign_and_broadcast(ledger_id)
       │
       ├─ Clone last update from ledger history
       │
       ├─ request_cosign(ledger_id, update)       ← BLOCKS RUN LOOP
       │    │
       │    ├─ Create notification_rx (broadcast receiver)
       │    ├─ Send cosign_update Kind 9101 (fire-and-forget)
       │    ├─ Subscribe to response for this request_id
       │    │
       │    └─ MINI EVENT LOOP (500ms deadline) ────────────────┐
       │         │                                             │
       │         │ select! {                                   │
       │         │   rx (oneshot) => return Ok(cosign_result)  │
       │         │                                             │
       │         │   notification_rx.recv() => {               │
       │         │     dispatch_or_extract_request(notif)      │
       │         │       → cosign_update: extract inline       │
       │         │       → other requests: dispatch to channel │
       │         │       → non-requests: dispatch normally     │
       │         │     drain response_rx → match pending       │
       │         │     drain ledger_rx → event store + history │
       │         │     process inline cosign_update requests   │
       │         │   }                                         │
       │         │                                             │
       │         │   sleep(deadline) => return Err(timeout)    │
       │         │ }                                           │
       │         └─────────────────────────────────────────────┘
       │
       │  On cosign failure: retry up to 3 times, 200ms sleep between
       │  TOTAL WORST CASE: 3 × 500ms + 2 × 200ms = 1.9s blocking
       │
       ├─ Apply partner signature to last history entry
       ├─ sign_last_update() (operator Schnorr)
       ├─ validate_chain_before_persist()
       ├─ persist_ledger_to_disk()
       └─ broadcast_last_update()  ← Kind 9100 published HERE (after cosign)
```

### Quorum Member Side (receive cosign → validate → sign → respond)

Two paths to receive cosign requests:

**Path A: Main run loop** (step 5b above)
```
handle_ledger_request()
  ├─ Pre-cosign drain: try_recv_ledger_update → event store + history
  ├─ catch_up_ledger_from_event_store()
  └─ process_cosign_request()
       ├─ Freshness check: local_len >= sequence_number?
       │   YES → sign and return
       │   NO  → catch_up_ledger_from_event_store()
       │         Re-check: still stale?
       │           YES → return error (NO blocking relay I/O)
       │           NO  → sign and return
       └─ send_ledger_response (Kind 9102, fire-and-forget)
```

**Path B: Inside operator's own cosign mini loop** (inline extraction)
```
(while waiting for OUR cosign response, process OTHER operators' cosign requests)
  ├─ notification_rx.recv() → dispatch_or_extract_request("cosign_update")
  │    → cosign_update requests extracted INLINE (never enter request_rx)
  │    → all other notifications dispatched to channels normally
  ├─ drain response_rx → match pending cosign responses
  ├─ drain ledger_rx → event store + history
  └─ process extracted cosign_update requests:
       └─ process_cosign_request() (same as above)
       └─ send_ledger_response()
```

## Response Delivery Path

```
Quorum member:
  send_ledger_response(Kind 9102)
    ├─ Tags: #e = request_id, #l = ledger_id, status = "ok"
    └─ send_event_nowait (fire-and-forget to relay)

        ↓ (relay propagation)

Operator (subscription: Kind 9102, #l filter = owned ledger IDs):
  broadcast::Receiver → handle_notification() → response_tx → response_rx

  Two consumers race for response_rx:
    a. Mini loop: try_recv_response → handle_cosign_response_only()
    b. Run loop (step 5d): try_recv_response → handle_ledger_response()
```

## Known Timing Constraints

| Operation | Typical | Worst Case | Blocks Run Loop? |
|-----------|---------|------------|-----------------|
| process_events() | <1ms (no events) | 100ms (timeout) | Yes |
| sign_and_broadcast (success) | 200-500ms | N/A | Yes |
| sign_and_broadcast (3× timeout) | N/A | 8s | Yes |
| fetch_recent_requests | 50-200ms | 5s | Yes |
| auto_import_joined_ledgers | 100ms | 10s+ | Yes |
| sync_wallet (electrs) | 100ms | 2s+ | Yes |
| process_cosign_request | <10ms | <50ms | No (returns immediately on stale) |

## Hypothetical Failure Mode: Serial Processing Cascade

### Setup
- 4 operators (Alice, Bob, Charlie, Diana), each joined to all others' ledgers
- Simulator sends concurrent transfers at 50 TPS target across all operators
- Each operator receives ~12 transfer_lock requests per second

### The Cascade

**Phase 1: Normal operation**
- Transfers arrive, cosign round-trip takes ~200ms, TPS is healthy

**Phase 2: Batch accumulation**
- process_events() drains a burst of notifications → 5-10 requests queued in request_rx
- Run loop drain (step 5b) processes them SEQUENTIALLY
- Each transfer_lock → sign_and_broadcast → 200ms (if cosign works)
- 10 requests × 200ms = 2 seconds of run loop blocking
- During those 2s, MORE requests accumulate in the Nostr channel

**Phase 3: Stale trigger**
- While Alice processes her batch (2s), Alice misses Bob's latest updates
  (they're in the broadcast buffer but process_events hasn't run)
- Bob sends cosign_update to Alice. Two possibilities:
  1. Alice is in her OWN cosign mini loop → mini loop drains ledger_rx → catches up → works
  2. Alice is processing a DIFFERENT request in the drain loop (transfer_lock #7 of 10) →
     Bob's cosign request sits in request_rx → not processed until Alice finishes her batch
- If Bob's cosign request isn't processed within 2s, Bob's request_cosign times out
- Bob retries (1s sleep + 2s timeout), but Alice may STILL be processing her batch
- All 3 of Bob's attempts timeout → sign_and_broadcast fails → Bob's transfer fails

**Phase 4: Bidirectional cascade**
- Alice's transfers also need cosign from Bob, but Bob is now stuck in his own 8s retry loop
- Both operators are blocking each other: Alice can't process Bob's cosign because
  she's in sign_and_broadcast, and Bob can't process Alice's because he's in sign_and_broadcast
- The mini loop handles cross-cosign within request_cosign, but the 2s timeout may expire
  before the OTHER operator's mini loop gets a chance to process
- Net effect: cosign success rate drops → retry loops consume more time → more timeouts

**Phase 5: Total breakdown**
- Each failed sign_and_broadcast takes 8s, during which no other requests are processed
- Queued requests timeout on the client (simulator) side
- "Timeout: Nostr error: Timeout waiting for response" appears because the operator
  never processes the request at all (it's stuck in sign_and_broadcast retry)

### Key Insight

The fundamental constraint is **single-threaded serial processing of requests in the drain loop**. The cosign mini loop provides cross-cosign processing, but ONLY while inside `request_cosign`. Between cosign calls (during the 1s retry sleep, during other request processing, during periodic tasks), cosign requests from others are buffered and not processed.

The 1s sleep between cosign retries (node.rs:7703) is particularly harmful: it blocks the run loop for a full second, during which NO events are processed at all.

## Confirmed Failure Modes (from metric data)

### Finding 1: Re-Queue Amplification (FIXED)

The cosign mini loop was draining ALL requests from `request_rx` each iteration, re-queuing non-cosign ones back to `request_tx` (same channel). With ~10 pending requests and the mini loop cycling every ~5ms, the same requests were re-queued ~400 times per 2s cosign attempt. Observed: **851 deferred/s per node** (Charlie peaked at 1,392/s), with **775,892 total re-queues on Charlie** during the test.

**Fix v1**: Batch-limited drain (max 10 per iteration) instead of draining everything. Insufficient — deferred rate remained ~1000-1300/s because cosign requests still get buried behind non-cosign requests in the same channel.

**Fix v2**: Inline extraction via `dispatch_or_extract_request()`. Cosign requests are intercepted directly from the broadcast notification stream and never enter `request_rx` at all. Non-cosign requests dispatch to channels normally. This eliminates re-queue amplification entirely — cosign requests are handled the instant the notification arrives, with zero deferred requests.

### Finding 2: Freshness Recovery Never Succeeds

`cosign_freshness_recovery_total{outcome=stale}` is the ONLY outcome — zero `recovered`. The event store catch-up and pre-cosign drain never bring the quorum member up to date. This means the prerequisite ledger update hasn't arrived at all by the time the cosign request is processed.

### Finding 3: Broadcast Channel Lag Drops Events

Alice lost 3,869 events and Bob lost 1,110 events to broadcast channel overflow (buffer=4096). These dropped events include ledger updates, which explains why freshness recovery never succeeds — the updates were literally never delivered to the mpsc channel.

### Finding 4: Cosign Latency Is Bimodal

- Success: 5-9ms average (very fast when it works)
- Timeout: exactly 2003ms (always hits the deadline, never partial)
- This means cosign either works immediately or doesn't work at all — no middle ground

### Finding 5: Timeout Occupies 30+ Minutes of Wall Time

225 S&B timeouts × 8s each = 1,803 seconds (30 minutes) of total blocking time across all nodes. During these windows, no other requests can be processed.

## Metrics Reference

### 1. Run Loop Iteration Timing
**What:** How long each full iteration of the run loop takes.
**Why:** If iterations are taking >2s, incoming cosign requests will timeout.

### 2. Request Queue Depth
**What:** How many requests are pending in request_rx at the time of drain.
**Why:** Large batches = long serial processing time.

### 3. sign_and_broadcast Duration (labeled by outcome)
**What:** How long sign_and_broadcast takes, labeled success/timeout/error.
**Why:** Directly measures the blocking time per request.

### 4. Cosign Round-Trip Latency (not just duration)
**What:** Time from cosign_update sent to response received, separately from total sign_and_broadcast.
**Why:** Distinguishes "quorum member is slow" from "operator is stuck".

### 5. Mini Loop Event Processing
**What:** How many ledger updates and cosign requests are processed inside the mini loop per cosign attempt.
**Why:** Confirms whether the mini loop is actually processing cross-cosign traffic.

### 6. Request Drain Batch Size
**What:** How many requests are processed in each drain loop execution.
**Why:** Batch size × per-request time = run loop blocking time.

### 7. Broadcast Channel Lag Events
**What:** Counter for Lagged errors on each broadcast receiver.
**Why:** If lag is occurring, events are being dropped.

### 8. Pre-Cosign Drain Effectiveness
**What:** How many updates drained and whether the target ledger was caught up.
**Why:** Confirms whether the drain is actually helping.

### 9. Deferred Request Count
**What:** How many non-cosign requests are re-queued from the mini loop.
**Why:** Measures how much "damage" the mini loop does to other request processing.

### 10. Cosign Response Delivery Timing
**What:** Time from quorum member sending response to operator receiving it.
**Why:** Tests whether the response subscription + broadcast channel is the bottleneck.
