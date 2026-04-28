# Chapter 8: Deposits and Transfers

> **Audience**: wallet users, integrators, operators, developers
> **Prereqs**: chapters 4, 6, 7
> **DEPs**: DEP-08, DEP-09

The previous chapters have set up the machinery — a ledger that grows by signed updates, a quorum that co-signs them, a UTXO that backs them. This chapter covers what you actually do with all of that: open an account, fund it, send value to someone else's account on the same operator, close the account when you're done. These are the two most common operations in the protocol, and they're the operations that have to feel boringly mechanical for the rest of the design to be worth anything.

A deposit is a stable, named balance on a single ledger. It is identified by a 16-byte `deposit_id` derived from a miniscript descriptor. It is opened, credited, debited, and eventually closed. While it exists, the depositor controls it by producing witnesses against the descriptor; the operator maintains the balance and broadcasts every change as a signed ledger update.

A transfer moves value between two deposits on the *same* ledger. It is a two-phase operation — a *lock* that earmarks funds against a spending condition, followed by a *complete* that satisfies the condition and moves the value (or a *fail* that releases it back). The lock is the leverage point: making the spending condition a miniscript policy turns transfers into a building block for richer flows like couriered cross-ledger swaps and HTLC relays.

This chapter walks through the lifecycle of both, with the wire shapes, the validation rules, and a worked example.

## Opening a deposit

A deposit comes into existence with a `DepositOpen` operation appended to a ledger. The wallet sends a `deposit_open` request to the operator over Nostr; the operator validates it, constructs the operation, runs it through the cosigning round, and broadcasts the signed update.

The operation carries (`deposits-protocol/src/messages/types.rs:201`):

- **`deposit_id`**: a 16-byte identifier, derived as `SHA256(descriptor)[0..16]`. The wallet computes this locally before sending the request; the operator verifies the derivation.
- **`descriptor`**: a miniscript policy string. For single-key deposits — by far the common case — this is `pk(<compressed_pubkey_hex>)`. The protocol also accepts `multi(k, key1, key2, ...)`, `and(pk(A), after(N))`, `or(pk(A), and(pk(B), sha256(H)))`, or any other valid miniscript.
- **`fees`**: a `FeeStructure` — the periodic custody fee schedule for this deposit (see [Chapter 10](10-fees-and-time.md)). May be `None` if the operator's defaults apply.
- **`transfer_fees`**: a `TransferFeeSchedule` — per-transfer fee, expressed as `fixed_msats + (amount_msats * rate_bps / 10000)`. Defaults to `fixed=2 msats, rate=20 bps` (`deposits-protocol/src/types/core.rs:161`).
- **`receive_requires_sig`**: a boolean. When true, incoming transfers, on-chain offers, and Lightning invoices for this deposit require a witness from the deposit's descriptor before the operator will create them. Prevents unsolicited crediting.
- **`fee_change_after_blocks`**, **`fee_change_notice_blocks`**, **`fee_change_limit_bps`**: governance parameters bounding when and by how much the operator can change fees on this deposit (see [Chapter 10](10-fees-and-time.md)).
- **`payment_hash`**, **`invoice`**, **`cosigner_guarantee_signature`**: optional fields that link a deposit-open to a specific funding event — used when opening a deposit as the destination of a "make a deposit by paying this invoice" flow. The body of this chapter assumes the simpler case where these are absent.

The operator's validations are layered. At wire-message validation time, the operator confirms the request is signed by an authorized pubkey (or by a delegated subkey, per DEP-04 attestation rules — see `request_handlers/deposits.rs`). At access-control time, denylist, pubkey allowlist, and domain-attestation gates run in order. If the operator has access control disabled, only the denylist runs. If the request fails any gate, the operator returns a structured error with the verifier and allowed domains the wallet can use to obtain an attestation.

At state-machine validation time (`deposits-core/src/ledger.rs:1505`), the operator confirms:

- The `deposit_id` is not already in `ledger.state.deposits` — duplicate IDs are rejected as `duplicate_deposit`.
- The `descriptor` size is within the quorum's `max_descriptor_bytes` limit (per DEP-05). Members who sign DEP-05's `QuorumAddMember` may set a maximum size they will tolerate; the strictest member's value is the binding limit.
- The fee schedule satisfies the quorum's minimum-fee policy. `quorum_policy.rs` enforces that a deposit's `fees.rate_bps` and `fees.fixed_msats` meet or exceed the strictest quorum member's `min_fee_bps` / `min_fee_fixed`. This protects members from inheriting low-fee deposits after a custody transfer.

If validation passes, the operator stages a `DepositOpen` update, runs the cosign round (Chapter 6), commits the staged update, and broadcasts the signed Kind:9100 event. The wallet picks up the update on its next sync.

The deposit starts at zero balance. The wallet retains a local *account record* with at least: the descriptor, the deposit_id, the ledger_id it lives on, and the operator's pubkey. From the wallet's side there is no need to track the chain — the operator does that — but the wallet must remember the descriptor in order to authorize future operations and to recover the deposit from a relay-only seed-restore.

### Recovering a deposit from seed

Because `deposit_id = SHA256(descriptor)[0..16]` is deterministic, a wallet that lost its local state can rederive every deposit it owns by walking its key tree, computing the deposit_id at each index, and querying any retaining relay for `Kind:9100` events tagged with that deposit_id (DEP-08 §"Deposit Recovery"). This is the protocol's only state-recovery mechanism: there is no remote backup, and there does not need to be one. The seed plus the relay is sufficient.

## Funding a deposit

Two paths in. On-chain and Lightning.

### On-chain funding

The wallet asks the operator for an on-chain funding address, the operator advertises one, the depositor pays, the operator credits. The wire flow:

1. The wallet sends a `funding_offer_request` for the deposit_id.
2. The operator generates an *offer* — a per-deposit Bitcoin address derived under their on-chain wallet, paired with a co-signed announcement that binds the address to the deposit. Offers are gift-wrapped (NIP-17) so only the requesting wallet can see them; that prevents a passive observer on the relay from correlating funding addresses to deposits. (DEP-10 covers offers in detail.)
3. The depositor sends Bitcoin to the address in a normal on-chain transaction.
4. The operator's daemon, watching its on-chain wallet via BDK, observes the deposit at some confirmation depth (typically 1 confirmation for low-value deposits, more for high-value).
5. The operator stages and commits an `InvoiceCredit` operation (yes, the on-chain credit reuses the `InvoiceCredit` discriminant — historically the credit operation was Lightning-only and the on-chain path was bolted on; in the protocol's typed enum it is one variant). The operation carries `payment_hash`, `deposit_id`, `amount`, an `invoice_id` derived from the offer, and a `sequence_number`.
6. The cosigners verify the credit doesn't push total deposit balances above reserves (the conformance check in `LedgerState::check_conformance` at `deposits-protocol/src/types/ledger_state.rs:692`). If reserves are insufficient, the credit is non-conforming and members refuse to sign. If reserves are fine, the credit is signed and broadcast.
7. The wallet sees the credit on its next sync. The deposit's `balance` increases by `amount`.

A note on the naming: "InvoiceCredit" reads oddly for an on-chain payment, but internally the operator treats both Lightning and on-chain incoming funds the same way — as the fulfillment of an invoice the operator created on the depositor's behalf. Wire format treats them uniformly (`invoice_id` is opaque). The `OnchainCredit` variant exists for direct address-to-address credits where there was no offer issued, but the offer-mediated path uses `InvoiceCredit`.

### Lightning funding

A Lightning invoice paid into the operator's node ends with the same `InvoiceCredit` operation. The mechanics — making the invoice, locking it as outgoing if the operator is paying out, fulfilling on preimage receipt — are covered in [Chapter 9](09-payment-channels.md). For this chapter, all that matters is that the credit lands in your deposit as a signed ledger update, the same shape as an on-chain credit.

## The transfer state machine

Now your deposit has a balance. You want to send value to someone else's deposit on the same ledger. This is what a *transfer* is for.

Transfers are two-phase. There is no single "send" operation. Instead:

```
TransferLock  → [pending_transfers]
                  ├─ TransferComplete → funds to destination, fee to operator
                  └─ TransferFail (timeout) → funds back to source, smaller fee
```

The lock-then-resolve shape is what makes transfers composable with hash-locked-contract bridges, courier routes, and conditional payments. Even a "boring" key-locked transfer goes through this machine; it just resolves on the same block as the lock.

### Phase 1: TransferLock

The wallet computes the transfer parameters, signs them with the source-deposit's descriptor key, and sends a `transfer_lock` request. The operator validates and stages a `TransferLock` operation (`deposits-protocol/src/messages/types.rs:314`):

- **`nonce`**: 32 random bytes. The nonce is wallet-controlled and serves a double duty — it makes the transfer_id unique even for repeated identical transfers, and it's the canonical embedding slot for fraud-proof binding (see [Chapter 11](11-fraud-proofs.md)).
- **`source_deposit_id`** / **`destination_deposit_id`**: 16-byte IDs. Both must exist on the ledger.
- **`amount`** (msats), **`fee`** (msats): the value moving and the fee charged. The `fee` must exactly match the source deposit's `TransferFeeSchedule`: `expected_fee = fixed_msats + (amount * rate_bps / 10000)`. Mismatches are rejected.
- **`completion_script`**: a miniscript policy. The recipient — or anyone who can satisfy the script — completes the transfer by providing a satisfying witness. Common cases: `pk(recipient_key)` for a vanilla send, `sha256(H)` for an HTLC, `and(pk(K), after(N))` for a timelocked send.
- **`timeout_height`**: a Bitcoin block height. After this height, the transfer is eligible for `TransferFail`. Bounded by the quorum's `max_transfer_timeout_blocks` (default 1008 blocks, ~1 week) — the operator rejects locks with deadlines further out, since an attacker could otherwise freeze the source's balance indefinitely.
- **`transfer_id`**: a 32-byte identifier the wallet derives as `SHA256(transfer_lock_signing_message(...))`. Deterministic from the inputs, so the wallet can compute it before submitting and use it as a primary key.
- **`witness`**: a `DescriptorWitness` (a stack of byte arrays) satisfying the source deposit's descriptor against the signing message. For a `pk()` deposit this is one 64-byte Schnorr signature.

State change on apply (`deposits-protocol/src/types/ledger_state.rs:556`): the source deposit's `locked_balance` increases by `amount + fee`. The source deposit's `balance` does *not* decrease — the balance is the total obligation, and `available_balance() = balance - locked_balance` is what's spendable. A lock just says "this much of the balance is committed to a pending transfer; you can't spend it elsewhere until it resolves." A `PendingTransfer` record is inserted into `state.pending_transfers` keyed by `transfer_id`, carrying everything needed to settle the transfer later.

The operator returns the new sequence number and event id to the wallet. At this point the funds are not yet at the destination — they're in escrow on the source.

### Phase 2a: TransferComplete

To complete a transfer, someone — usually the recipient — provides a `script_witness` that satisfies the `completion_script`. The wallet (or the courier, or whoever holds the spending evidence) sends a `transfer_complete` request to the operator with the `transfer_id` and the witness. The operator stages a `TransferComplete` operation:

```rust
TransferComplete {
    transfer_id: [u8; 32],
    script_witness: DescriptorWitness,
}
```

State change on apply (`deposits-protocol/src/types/ledger_state.rs:596`):

1. Look up `pending_transfers[transfer_id]` and remove it.
2. Source: `locked_balance -= (amount + fee)`. `balance -= amount`. (The fee leaves the source as well, but it isn't tracked as a per-deposit balance — it becomes operator income.)
3. Destination: `balance += amount`. (`locked_balance` does not change on the destination — the destination's balance is what the depositor sees as available right away.)
4. Operator's `fees_accumulated` increases by `fee`. This pool is later distributed to quorum members per their `compensation_*` settings ([Chapter 10](10-fees-and-time.md)).

The witness verification is a conformance check: members refuse to cosign a `TransferComplete` whose `script_witness` doesn't satisfy the lock's `completion_script` against the transfer_id. An operator who tried to drain a lock without a valid witness would be producing a non-conforming update — fraud-proof material.

### Phase 2b: TransferFail

If `timeout_height` passes without a successful completion, anyone can cause the operator to fail the transfer. In practice the operator does it themselves to free up the source's locked balance; the wallet doesn't have to ask. A `TransferFail` operation carries:

```rust
TransferFail {
    transfer_id: [u8; 32],
    block_hash: [u8; 32],   // the block hash at timeout_height
    reason: u8,             // 1 = timeout. 0 is reserved.
}
```

State change on apply (`deposits-protocol/src/types/ledger_state.rs:614`):

1. Look up `pending_transfers[transfer_id]` and remove it.
2. Source: `locked_balance -= (amount + fee)`. The source's `balance` is reduced by the *fixed* portion of the source deposit's transfer fee (the amount the operator charges for holding the lock and timing it out). The amount and the proportional fee are returned to the source.
3. Operator's `fees_accumulated` increases by the fixed fee.

This is a smaller penalty than a successful transfer's full fee, but it is non-zero — the operator did real work holding the lock. The fixed-fee charge prevents an attacker from spamming locks-then-timeouts to grief the operator.

The `block_hash` field is part of the `TransferFail` so that fraud-proof verifiers can confirm the operator actually waited until the claimed timeout block (the hash binds the failure to a specific Bitcoin block on chain). An operator who failed a transfer one block early would be producing a non-conforming update.

## Why two phases instead of one?

This is the question worth pausing on. A naive design would have a single `Transfer` operation that moves `amount` from source to destination immediately and charges the fee at the same time. Why don't we do that?

Because the lock's `completion_script` is the entire reason this protocol can do anything beyond intra-ledger sends. Three concrete things need it:

**HTLC bridges and courier routes.** A courier holding deposits on ledgers A and B atomically swaps value across them by anchoring both legs to the same SHA256 preimage. The wallet locks `amount + fee` on A with `completion_script = sha256(H)`. The courier locks `amount' - courier_fee` on B with the same `sha256(H)`. The recipient on B reveals the preimage to complete leg B. The courier observes the preimage on B's relay, uses it to complete leg A, and the swap is atomic. If either leg times out, the corresponding side is restored. [Chapter 16](16-couriers.md) walks through this in detail. None of it is possible without the script-locked phase.

**Conditional transfers.** A wallet can lock `(pk(K) AND after(N))` to make a payment that the recipient can only claim after a future block — a timed gift, an escrow release. Lock `multi(2, key1, key2)` for a two-of-two release, where both parties have to be online to settle. The miniscript surface gives the wallet expressive control over when and how a transfer can land.

**Multi-hop payments within a ledger.** Less interesting than cross-ledger, but free as a side effect: a wallet can build a chain of locks on a single ledger and have them resolve in sequence.

The two-phase design also makes the protocol's atomicity story cleaner. A `TransferLock` followed by a `TransferComplete` is equivalent to a single send under the hood — but it's the *same* primitive that does the hash-locked bridge case. There is one transfer state machine, not two.

## Closing a deposit

`DepositClose` removes a deposit from the ledger. Two preconditions (`deposits-core/src/ledger.rs:1517`):

- The deposit's `balance` must be exactly zero. A non-zero balance returns `NonZeroBalance{balance}`.
- The deposit must have no outstanding invoices: `deposit.invoices.is_empty()`.

The wallet is expected to drain the deposit first — transfer the balance to another deposit, withdraw on-chain, or pay it out via Lightning — and then submit `deposit_close`. There's no implicit "drain and close" in one step; if you have 1 sat left over, you'll be told to clear it before closing.

A subtlety: the close-time check is on `balance`, not `available_balance`. Pending transfers contribute to `locked_balance`, and `locked_balance` is part of the `balance` total. So a deposit with one pending lock cannot be closed until the lock resolves (complete or fail). Wallets close cleanly by waiting for any in-flight locks to settle before submitting the close request.

After close, the `deposit_id` slot is freed but not reused — the same wallet pubkey can re-derive the same descriptor and re-open the deposit, but DEP-08 §"Open" rejects an open whose `deposit_id` is already in `ledger.state.deposits`. After close, the deposit is no longer in `state.deposits`, so the same descriptor can be reopened. Whether to do so is a wallet decision; usually rotating the key gives better unlinkability between successive deposits.

## Wallet-side concerns

A few practical points for someone writing wallet code or thinking about the wallet/operator boundary.

### Authorization

The wallet authorizes every operation by signing it with the deposit's descriptor key. For `pk()` deposits this is a single Schnorr signature over a per-operation signing message:

- Transfer lock: `transfer_lock_signing_message(nonce, src, dst, amount, fee, script, timeout)`
- Withdrawal: `withdrawal_signing_message(nonce, deposit_id, address, amount, fee)`
- Key rotation: `SHA256(new_descriptor)`
- Receive authorization (when `receive_requires_sig`): the `transfer_id` for transfers, or the zero-padded `deposit_id` for offers and invoices.

The operator's verification path is the function `verify_witness` in `deposits-core/src/descriptor.rs`. It optimizes the `pk()` case to a single Schnorr verify; for any other miniscript, it parses the descriptor and evaluates the witness stack against the policy. If the descriptor is `multi(2, A, B)`, the witness stack contains two signatures and both are checked.

### Receiving offline

A wallet does not need to be online to receive. Credits are posted to the ledger by the operator unilaterally — `InvoiceCredit` and `OnchainCredit` need only the operator's signature plus the cosignatures. When the wallet next syncs, it reads the new updates from the relay, applies them locally, and the deposit balance reflects the credits.

The one place a wallet must be online is when `receive_requires_sig` is true and someone is trying to credit the deposit. In that case the operator can't proceed without a witness from the wallet authorizing the receive. Wallets that want to receive offline and unconditionally set `receive_requires_sig=false` at deposit-open time. The tradeoff is that a malicious operator can crowd the deposit with unsolicited credits, which doesn't lose the wallet money but does pollute the deposit's history.

### Spending

To spend, the wallet:

1. Constructs the operation parameters locally (computes `transfer_id`, picks `nonce`, signs the signing message).
2. Sends a request — `transfer_lock`, `transfer_complete`, `withdraw`, etc. — to the operator's pubkey on the messaging relay (Kind:20100).
3. Awaits a response. The operator either confirms (with the new sequence number and event_id) or rejects with a structured error.
4. On confirmation, the wallet sees the resulting `Kind:9100` ledger update on the next sync — the same path as receiving credits. The update is the authoritative record.

If the operator never responds, the wallet escalates via DEP-12 certified delivery — see [Chapter 15](15-delivery-escalation.md). A quorum member embeds the request hash on their own ledger, starts the `service_response_blocks` clock, and if the operator doesn't process the request within that window the censorship is fraud-proof material.

### Atomicity guarantees

Within a single ledger, transfers are atomic with respect to operator commits. A `TransferComplete` either lands on the chain — committed by the operator, cosigned by the quorum, broadcast on Kind:9100 — or it doesn't. There is no partial state, no half-applied transfer, no race between source-debit and destination-credit. The operation is one update; the state transition happens in one apply step.

Across ledgers, atomicity is recovered with a different primitive: the courier's HTLC, where the same preimage settles two locks on two ledgers and the locks' timeouts ensure neither side can be left holding. Cross-ledger transfers are not an extension of the single-ledger transfer; they are a *coordination* of two single-ledger transfers, glued together by hash-locked completion scripts. [Chapter 16](16-couriers.md) is where that story lives.

## A worked example

Let's walk through opening, funding, transferring, and closing on a small example. Three participants: Alice (depositor), Bob (depositor), and Op (operator running ledger L).

**Step 1: Alice opens a deposit.** Alice's wallet picks key index 0, derives compressed pubkey `A_pk`, computes descriptor `pk(A_pk_hex)`, and computes `deposit_id_A = SHA256(descriptor)[0..16] = 0xab12...`. She sends `deposit_open` to Op with the descriptor, default fees, `receive_requires_sig=false`. Op validates, stages, cosigns, and broadcasts a `DepositOpen{deposit_id_A, descriptor: "pk(A_pk_hex)", ...}` update at sequence 100. Alice's wallet sees it on next sync. Balance: 0 msats.

**Step 2: Alice funds with 10K sats on-chain.** Alice asks Op for an on-chain offer for `deposit_id_A`. Op derives a fresh BDK address `bc1q...alice_offer` and gift-wraps the announcement. Alice sends 10,000 sats to that address. After 1 confirmation, Op observes the funding TX, stages an `InvoiceCredit{payment_hash, deposit_id_A, amount: 10_000_000 msats, invoice_id: <offer_id>}` at sequence 101, runs the cosign round, and broadcasts. Alice's wallet sees the credit. Balance: 10,000,000 msats. Locked: 0.

**Step 3: Bob opens a deposit on the same ledger.** Symmetric to Alice: `deposit_id_B = 0xcd34...`. The operator broadcasts `DepositOpen{deposit_id_B, ...}` at sequence 102. Both Alice and Bob's wallets, and the relay, now see both deposits.

**Step 4: Alice transfers 3K sats to Bob.** Alice's wallet picks a random nonce `n`, picks `completion_script = "pk(B_pk_hex)"` (vanilla recipient-signed), picks `timeout_height = current_height + 144` (one day), computes `transfer_id = SHA256(transfer_lock_signing_message(n, A_id, B_id, 3_000_000, fee, "pk(B_pk_hex)", timeout))`. Bob's deposit's transfer fee schedule is `fixed=2 msats, rate=20 bps`; on a 3,000,000 msat transfer that's `2 + (3_000_000 * 20 / 10000) = 2 + 6_000 = 6_002 msats` — but the fee is paid by the *source*, so it's Alice's source-deposit fee schedule that applies. Assume Alice's deposit has the same defaults: `fee = 6_002 msats`. Alice signs `transfer_lock_signing_message(...)` with `A_pk` and sends `transfer_lock` to Op.

Op validates (signature, fee match, sufficient balance, timeout within max), stages `TransferLock{nonce: n, src: A_id, dst: B_id, amount: 3_000_000, fee: 6_002, completion_script: "pk(B_pk_hex)", timeout_height, transfer_id, witness: <Alice's signature>}` at sequence 103. Cosigners verify: Alice's signature, fee correctness, balance is sufficient (Alice has 10,000,000 ≥ 3,006,002). Cosign passes. Op commits and broadcasts.

Post-`TransferLock` state on ledger L:
```
deposits[A_id]: balance = 10_000_000, locked_balance = 3_006_002  (available: 6_993_998)
deposits[B_id]: balance = 0,          locked_balance = 0
pending_transfers[transfer_id] = PendingTransfer { ... }
```

**Step 5: Bob completes the transfer.** Bob's wallet sees the new lock on next sync, recognizes `B_id` as the destination, signs the `transfer_id` with `B_pk` to satisfy the `pk(B_pk_hex)` completion script. Bob sends `transfer_complete` with the witness. Op validates (witness satisfies the script, transfer is still pending and not timed out), stages `TransferComplete{transfer_id, script_witness: <Bob's sig>}` at sequence 104. Cosigners verify witness against `completion_script`. Cosign passes. Op commits and broadcasts.

Post-`TransferComplete` state on ledger L:
```
deposits[A_id]: balance = 7_000_000, locked_balance = 0       (available: 7_000_000)
deposits[B_id]: balance = 3_000_000, locked_balance = 0       (available: 3_000_000)
pending_transfers: empty
fees_accumulated += 6_002 msats
```

Note that on apply, Alice's `balance` decreases by `amount` only (3,000,000), not `amount + fee`. The 6,002 msat fee is tracked as operator income in `fees_accumulated` and is reconciled against reserves at fee-collection time (DEP-07's `FeeCollect`). The `locked_balance` field's only job is to constrain `available_balance` while the lock is pending; the fee bookkeeping is separate. See the protocol comment at `deposits-protocol/src/types/ledger_state.rs:600` for the rationale.

**Step 6: Alice closes her deposit.** After moving the remaining 7_000_000 msats out (a withdrawal, another transfer, a Lightning payment), Alice's `balance = 0`. She sends `deposit_close{deposit_id_A}`. Op validates (`balance == 0`, no outstanding invoices), stages `DepositClose{deposit_id: A_id}` at sequence N, cosigns, broadcasts. Alice's wallet sees the close on next sync and removes the account record locally.

End state: Bob has 3_000_000 msats on the ledger; Alice has nothing. The operator earned 6_002 msats in fees (plus per-block balance fees for the time the deposit was open, see [Chapter 10](10-fees-and-time.md)). The whole sequence took 5 ledger updates: open, credit, lock, complete, close (plus open of Bob's deposit, in the middle).

## Where this leads

[Chapter 9](09-payment-channels.md) covers Lightning bridging — how `InvoiceLock`, `InvoiceFulfill`, and `InvoiceFail` extend the same two-phase machine to cross the boundary between the deposits ledger and the operator's Lightning node, and how on-chain offers and withdrawals work end-to-end.
