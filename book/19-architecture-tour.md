# Chapter 19: Architecture Tour

> **Audience**: developers, integrators
> **Prereqs**: Part II (Chapters 4–10)
> **DEPs**: none directly — this chapter maps DEPs onto code

This chapter is a guided tour of the reference implementation. It tells you what each crate does, what the load-bearing types are, and where to look when you want to trace a particular protocol behavior to its source. It is also the grounding chapter for the rest of Part V — Chapters 20–22 dive into the daemon, wallet, and test infrastructure assuming you have the map this chapter provides.

The implementation is a Rust workspace with nine crates. Build it from the repository root:

```bash
cargo build --workspace --release
```

That produces binaries under `target/release/`: `deposits-node`, `deposits-wallet`, `deposits-attest`, `deposits-lnurl`, plus a handful of testing utilities under `deposits-tools` and `deposits-node`.

## The crates at a glance

```
                 ┌─────────────────────────┐
                 │   deposits-protocol     │  Wire format, types, TLV.
                 │   (no I/O, no state)    │  The shared vocabulary.
                 └────────────┬────────────┘
                              │
                              v
                 ┌─────────────────────────┐
                 │     deposits-core       │  State machine, validation,
                 │  (no I/O, no network)   │  signing, conformance.
                 └────────────┬────────────┘
                              │
            ┌─────────────────┼──────────────────┐
            v                 v                  v
   ┌────────────────┐ ┌───────────────┐ ┌──────────────────┐
   │ deposits-node  │ │deposits-wallet│ │ deposits-test    │
   │  (the daemon)  │ │  (the CLI)    │ │ (integration     │
   │  BDK + Nostr   │ │ Nostr client  │ │  test harness)   │
   └────────────────┘ └───────────────┘ └──────────────────┘
                              │
                              v (consumed by both node + wallet)
   ┌─────────────────────┐  ┌──────────────────────┐  ┌───────────────────┐
   │ deposits-attestation│  │  deposits-ringsig    │  │  deposits-lnurl   │
   │  (Web2 ↔ npub link) │  │  (bLSAG anonymous    │  │  (LUD-06/16 ↔     │
   │                     │  │   web-of-trust)      │  │   make_invoice)   │
   └─────────────────────┘  └──────────────────────┘  └───────────────────┘

                 ┌─────────────────────────┐
                 │     deposits-tools      │  Admin scripts, regtest
                 │                         │  setup, decode-updates,
                 │                         │  treasury helpers.
                 └─────────────────────────┘
```

The arrows are dependency direction: `protocol` is at the bottom of the stack, every other crate uses it. `core` builds the state machine on top of `protocol`. `node` and `wallet` are the two top-level consumers — one runs as a daemon, the other as a CLI client.

The strict layering matters for testability. Because `protocol` and `core` have no I/O, they can be tested as pure functions. The integration test crate (`deposits-test`) exercises multi-operator scenarios at the `core` level for fast feedback, then escalates to full daemon-cluster Tier-3 tests when wire-level coverage is needed. See [Chapter 22](22-testing-and-fuzzing.md).

## deposits-protocol

`deposits-protocol/src/lib.rs`. The smallest, oldest, most stable crate.

Defines the wire format and the typed representations every other crate manipulates. No state machine, no I/O, no business rules — just types and serializers.

Module map:

| Module | What it owns |
|---|---|
| `types/` | `LedgerState`, `Deposit`, `QuorumMember`, `SignedLedgerUpdate`, `CosignEntry`, `DisputeState`, `QuorumState`, `ConformanceViolation` |
| `messages/` | `LedgerOperation` enum (every operation that can land on a ledger), `DepositsMessage` (peer-to-peer messages above ledger updates) |
| `tlv.rs` | TLV encoder/decoder. Ledger updates are TLV-encoded, then base64'd into Nostr event content |
| `fraud.rs` | `FraudProof`, `FraudBroadcast`, `FraudEvidence`, `ProofEmbedding`, `CausalLink`. The shapes a fraud proof takes on the wire |
| `wire_messages.rs` | The on-wire envelopes for cosign requests, consent requests, etc. |
| `signature_utils.rs` | Helpers for hashing-to-signing-data and signature verification |
| `constants.rs` | Protocol constants: `MAX_QUORUM_SIZE_POLICY = 8`, `MAX_DISPUTANTS = 15`, etc. |
| `error.rs` | `DepositsError`, `DepositsResult` |

The single most important type in this crate is `LedgerOperation` (in `messages/types.rs`). Every variant corresponds to a class of state-machine transition — `LedgerOpen`, `DepositOpen`, `InvoiceCredit`, `InvoiceLock`, `InvoiceFulfill`, `TransferLock`, `TransferComplete`, `FeeChange`, `QuorumBegin`, `DisputeEnter`, `DisputeArmed`, `DisputeAcquire`, and so on. If you want to know what operations the protocol supports, read this enum.

The second most important type is `SignedLedgerUpdate` (in `types/ledger_state.rs`). This is the wire shape of a single update — operation bytes + chain context (`previous_hash`, `sequence_number`, `block_height`) + signatures (operator + cosignatures). Every event on the relay's `Kind:9100` (ledger update) is one of these, TLV-encoded, base64-ed.

## deposits-core

`deposits-core/src/lib.rs`. Builds the state machine and validation logic on top of `protocol`. Still no I/O.

Module map:

| Module | What it owns |
|---|---|
| `ledger.rs` | `Ledger` (in-memory chain + state), `stage_operation`, `commit_staged`, `apply_operation`, `validate_operation`. The state machine driver. |
| `tapscript_reserves.rs` | The Taproot script tree for the reserves UTXO. `TaprootReservesInfo`, `LotteryOutput`, `create_partial_reveal_witness`. |
| `descriptor.rs` | The miniscript descriptors for deposit spending conditions. |
| `quorum_policy.rs` | Fee-schedule policy enforcement (member minimum-fee guards) and the Q≤8 cap. |
| `event_store.rs` | An in-memory event store used during gap-fill catch-up — a content-addressed cache of `SignedLedgerUpdate`s the daemon has seen on the relay. |
| `signing.rs` | Operator + cosigner signing helpers, signing-data construction. |
| `validation.rs` | `LedgerExport` validation — what import_ledger uses to verify a foreign ledger's chain before accepting it. |
| `operation_validation.rs` | Per-operation validators — the ones that can return rejection reasons. |
| `message_validation.rs` | Validation helpers for inbound peer messages. |
| `message_handlers/` | Operation-specific handler logic (lock/fulfill/fail, transfer state machine). |

`Ledger::stage_operation` and `Ledger::commit_staged` are the operator's two-phase commit primitive. `stage_operation` validates against current state and produces a `StagedUpdate` (operation + unsigned `SignedLedgerUpdate`); `commit_staged` advances the state machine and pushes the signed update to history. These are the methods the daemon's actor (Chapter 20) calls when an operator commits.

`LedgerState::apply` is the pure state-transition function. Given a current `LedgerState` and a `LedgerOperation`, it produces the next `LedgerState` (or returns a `DepositsError` for a non-conforming op). This is the function fraud-proof verifiers exercise when they replay a chain.

`Ledger::checked_apply` is the conformance-checked variant: it runs `apply` *and* checks that the resulting state doesn't violate operator obligations (over-promising against reserves, fee underflow, dispute-state mismatch). This is what members run before co-signing.

## deposits-node

`deposits-node/src/lib.rs`. The daemon — operators run this. Also produces the wallet-CLI binary in `deposits-node/src/bin/` and several utility binaries.

This is the largest crate. Two top-level pieces:

### `handler.rs`

The `DepositsHandler` owns the loaded ledgers map (`Mutex<HashMap<String, Arc<RwLock<Ledger>>>>`), the persistence layer (`<id>.jsonl` files in `wallet/ledgers/`), the message-queue plumbing, and the disk reload paths. It does *not* speak Nostr or Bitcoin — those are wired in by `Node`.

### `node/`

The `Node` struct is the daemon's heart. Its module organization:

| File | What it does |
|---|---|
| `mod.rs` | The `Node` struct definition. All fields documented. |
| `init.rs` | `Node::new` — loads ledgers from disk, spawns the actor pool, parks the actor outbox receiver, opens Nostr subscriptions. |
| `main_loop.rs` | `Node::run` — the long-running event loop. Drains inbound Nostr events, processes per-ledger work, runs periodic tasks, ticks the dispute pipeline. |
| `inbound.rs` | `handle_ledger_update` — what happens when a `Kind:9100` ledger update arrives. Validation, dispatch to actor + handler apply path. |
| `operations.rs` | `commit_operation` — the operator-side commit shim. Dispatches to the per-ledger actor. |
| `coordination.rs` | `request_cosign` — fan-out of cosign requests to quorum members. |
| `dispute.rs` | The recovery pipeline: `auto_arm`, `auto_confiscate`, `auto_lottery_claim_or_yield`. |
| `auto_tasks.rs` | Periodic background tasks: deposit auto-credit, auto-complete transfers, fee assessment. |
| `ledger_actor.rs` | The per-ledger actor. One tokio task per ledger, owns the apply path. (Chapter 20.) |
| `ledger_queries.rs` | Read-side queries the daemon exposes to the CLI: `open_ledger`, `import_ledger`, `info`, etc. |
| `request_handlers/` | Per-message-type request handlers (`deposits.rs`, `transfer.rs`, `invoice.rs`, `quorum.rs`, `cosign.rs`, `health.rs`, `admin.rs`). |
| `nostr.rs` | The Nostr client wrapper: subscriptions, publish, kind constants, gift-wrap helpers. |
| `wallet.rs` | BDK wallet integration — operator's on-chain wallet, used to spend reserves and broadcast confiscation TXs. |
| `metrics.rs` | Prometheus exporters. |

The actor model is the most consequential architectural decision in the daemon. Every loaded ledger gets a dedicated tokio task that owns the apply path; the actor's `Ledger` is the same `Arc<RwLock<Ledger>>` the handler exposes via `handler.ledgers`. Single source of truth, single writer per ledger. Chapter 20 walks through this in detail.

### Other binaries in `deposits-node`

- `deposits-node` — the daemon itself (the `run` subcommand) plus all the admin commands (`info`, `address`, `reserves create`, `ledger open`, `quorum add`, `quorum begin`, etc.).
- `nostr-ping`, `nostr-bench` — relay testing utilities.
- `transfer-simulator` — load generator.
- `htlc-agent` — courier daemon (operates the routing logic from [Chapter 16](16-couriers.md)).

## deposits-wallet

`deposits-wallet/src/main.rs`. The depositor's CLI client. Subcommands for:

- Discovery: finding operators on the relay (`discover`).
- Account ops: opening deposits, querying balance, listing transfers.
- Spending: lock/fulfill/fail transfers, paying invoices, requesting on-chain exits.
- Escalation: sending `delivery_embed` requests when an operator stops responding.
- Recovery: replaying a ledger from the relay to detect changes in custody.

The wallet has no daemon-side code; it speaks Nostr directly to the relay and waits for the operator's response (or escalates if none arrives).

## deposits-attestation

`deposits-attestation/`. The attestation service implementation — runs as a Web2 verifier (domain ownership via DNS or HTTPS, Lightning address control via LNURL ping) and issues signed attestations linking those identifiers to operator npubs. Chapter 17 covers the protocol.

The crate also includes the verifier-side code that wallets use to check incoming attestations — so wallets don't need a separate dependency on this crate just to validate.

## deposits-ringsig

`deposits-ringsig/`. bLSAG ring signatures over secp256k1, used by the anonymous web-of-trust scheme. A wallet that wants to send an authenticated request to an operator without revealing which member of a known set it is uses this crate to produce a ring signature; the operator verifies the signature with the same crate.

The wire format is documented in `RING-SIGNATURES.md` at the repo root and contextualized in [Chapter 18](18-ring-signatures.md).

## deposits-lnurl

`deposits-lnurl/`. A bridge from LUD-06/LUD-16 (the Lightning-address request protocol Lightning wallets speak) to the deposits protocol's `make_invoice` request. Operators run this if they want to expose a Lightning-address-shaped front-end to wallets that don't speak deposits-protocol natively.

Each LNURL request to the gateway becomes a deposits `make_invoice` request to the operator's daemon over Nostr; the daemon returns a co-signed BOLT-11 invoice; the gateway returns it to the LUD-06 caller as a normal Lightning-address response.

## deposits-tools

`deposits-tools/`. Operational utilities and the regtest cluster harness:

- `bin/setup.sh` — the canonical "give me an N-operator cluster" script. Runs Bitcoin Core in regtest, creates wallets, funds operators, opens ledgers, forms quorums, activates them.
- `decode-updates` — given a `<id>.jsonl` file, pretty-print each update's operation and signatures.
- `treasury-address`, `treasury-send` — sweep helpers for moving operator income.
- `discover` — wallet-side discovery probe.
- `replay-ledger` — fetch every update for a ledger from the relay and reconstruct the chain locally.
- `standalone-reserves-demo` — a minimal example of constructing reserves UTXOs + lottery outputs without a full daemon.

## deposits-test

`deposits-test/src/lib.rs`. The integration test harness.

Two flavors of test:

- **In-process simulations** (`tests/`): multi-operator scenarios that exercise the protocol at the `core` crate level, no daemon, no Nostr, no Bitcoin. Examples: `defend_49pct.rs`, `final_game.rs`, `fuzz_protocol.rs` (the adversarial protocol fuzzer). These run in seconds; they're the workhorse for protocol invariants.
- **Tier-3 cluster tests** (`tests/dispute_initiation.rs`, `tests/fraud_proof_*.rs`, `tests/cross_ledger_route.rs`, `tests/equivocation_broadcast.rs`, `tests/delivery_embed.rs`, `tests/actor_shadow_consistency.rs`): tests that need a fresh `setup.sh` cluster running. Marked `#[ignore]`; opted in via `cargo test -- --ignored`.

Tier-3 tests are not idempotent — fraud-proof tests dispute a ledger, so re-running on the same cluster fails. Run each on a freshly-set-up cluster.

The `deposits-test/src/regtest.rs` module contains the helpers that drive cluster tests: cluster discovery, peer queries, fraud-proof construction, marker polling.

## How a request flows through the system

To make this concrete, here is what happens when a wallet sends a `transfer_lock` request to an operator. (Detailed in Chapter 8.)

1. **Wallet** (`deposits-wallet`): user runs `deposits-wallet transfer lock --from D1 --to D2 --amount 1000`. The CLI builds a `LedgerRequest` payload, signs it with the deposit's wallet key, and publishes a Nostr `Kind:20100` (request) event tagged with the operator's pubkey and the ledger ID.

2. **Relay**: the Nostr relay (strfry, in the reference deployment) receives the event and forwards it to subscribers. The operator's daemon is subscribed to events tagged with its pubkey on the messaging relay.

3. **Daemon inbound** (`deposits-node/src/node/main_loop.rs`): the main event loop receives the event, decodes it, and dispatches to `request_handlers/transfer.rs::handle_transfer_lock_request`.

4. **Validation** (`request_handlers/transfer.rs`): the handler verifies the wallet's signature, looks up the source deposit, checks balance availability, and constructs a `LedgerOperation::TransferLock`.

5. **Commit** (`operations.rs::commit_operation`): the handler calls `commit_operation`, which:
   - Acquires the per-ledger staging lock.
   - Snapshots block height and hash from the BDK wallet.
   - Sends a `LedgerEvent::Commit` to the per-ledger actor's inbox.
   - Awaits the reply.

6. **Actor** (`ledger_actor.rs::handle_commit`): the actor stages the operation against its `Arc<RwLock<Ledger>>`, requests cosignatures from quorum members via the outbox (which the main loop's drainer routes to `coordination.rs::request_cosign`), operator-signs the staged update, applies it via `commit_staged`, persists to `<id>.actor.log`, and emits a `Broadcast` outbox event with a oneshot reply.

7. **Broadcast** (`nostr.rs::broadcast_ledger_update`): the drainer's broadcast handler publishes a `Kind:9100` event with the TLV-encoded signed update and replies the event id back to the actor.

8. **Actor replies** to `commit_operation` with `CommitResult { event_id, update }`. The shim persists `<id>.jsonl` (handler.persist_ledger_to_disk) for crash safety.

9. **Response** (`request_handlers/transfer.rs`): the handler sends a `Kind:20101` (response) event back to the wallet with the new lock's deposit ID and sequence number.

10. **Wallet receives** the response and persists it locally. Done.

If you can trace this end-to-end through the source, you understand the daemon. Chapter 20 covers the actor model and main loop in more detail; this is the orientation.

## What stays in your head

- `deposits-protocol` defines wire types. `deposits-core` defines the state machine. `deposits-node` runs the daemon. `deposits-wallet` is the CLI.
- Inside `deposits-node`, the `node/` module is where the action is: `inbound.rs` for incoming events, `operations.rs` for outgoing commits, `ledger_actor.rs` for per-ledger state ownership, `dispute.rs` for the recovery pipeline.
- The single source of truth for any ledger's `Ledger` value is the `Arc<RwLock<Ledger>>` shared between `handler.ledgers` and the per-ledger actor.
- When a chapter says "this lands in `deposits-core/src/ledger.rs:1107`", it means literally that file, that line. The protocol-level chapters in Part II will reference `deposits-protocol` and `deposits-core`. Part V chapters reference `deposits-node` heavily.

## Where this leads

[Chapter 20](20-the-daemon.md) opens up the daemon: the actor model, the main loop, the inbound dispatcher, the persistence layer, the dispute drivers. After that [Chapter 21](21-the-wallet.md) covers the wallet client, [Chapter 22](22-testing-and-fuzzing.md) covers the test infrastructure, and [Chapter 23](23-operations.md) covers production deployment.
