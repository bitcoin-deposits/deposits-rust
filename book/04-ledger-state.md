# Chapter 4: Ledger State Model

> **Audience**: developers, integrators, operators
> **Prereqs**: chapters 1, 2
> **DEPs**: DEP-02

A ledger is the protocol's unit of custody, and its central data structure. This chapter teaches what a ledger is, what an update looks like on the wire, what operations can land in it, how the hash chain is built, and what state the operator and quorum maintain. The goal is that after reading it you can pick up `DEP-02` for any precise question and read it without translation, and you can open `deposits-protocol/src/types/ledger_state.rs` or `deposits-core/src/ledger.rs` and know what you are looking at.

## What a ledger is

A ledger is an append-only chain of signed updates owned by one operator at a time. It has a stable identity that survives operator changes, a reserves UTXO that backs every deposit on it, a quorum of cosigners, and a history that anyone can replay.

Three things define it at birth:

- An **operator key** — the secp256k1 pubkey of the operator who opened it.
- A **reserves identifier** — a string identifying the on-chain output that backs deposits (typically a `txid:vout`, or a Taproot address while reserves are being rotated).
- A **genesis block** — the Bitcoin block height at which the ledger was opened.

These three are hashed together to produce the 32-byte `ledger_id`:

    ledger_id = SHA256(operator_pubkey || reserves_id || genesis_block_le)

This computation lives in `LedgerState::compute_ledger_id` (`deposits-protocol/src/types/ledger_state.rs:134`). The ledger_id is fixed for the life of the ledger. After a custody transfer the `operator_key` changes, the reserves move to a new UTXO at `QuorumBegin`, but the ledger_id stays the same — the deposits keep their addresses, wallets keep finding their funds.

A ledger contains one current operator (the only party who can sign new updates), one reserves UTXO (the on-chain anchor), one quorum (the active set of cosigners, plus a `next_quorum_members` set staged for the next rotation), and a state machine driven by every signed update appended so far. Two distinct hashes track its progress:

- `chain_tip_hash` — the chain hash of the most recent committed update. This is what the next update will name as its `previous_hash`.
- `sequence` — a monotonically-increasing u64. The first update is sequence 0, every subsequent update is exactly one higher.

When you load a ledger from disk and want to know "is this the latest version", these two fields are what you compare.

## The shape of a signed update

Every state change is a single `SignedLedgerUpdate`. It is the on-the-wire shape that travels over Nostr, the on-disk shape stored in `wallet/ledgers/<id>.jsonl`, and the in-memory shape every component of the system passes around. Its definition is in `deposits-protocol/src/types/updates.rs:41`. The fields are:

| Field | Bytes | What it is |
|---|---:|---|
| `operator_id` | 33 | Operator's compressed secp256k1 pubkey |
| `ledger_id` | 32 | The chain identity (hash above) |
| `sequence_number` | 8 | u64, monotonic |
| `previous_hash` | 32 | Chain hash of the prior update |
| `message` | variable | The TLV-encoded `LedgerOperation` |
| `block_height` | 4 | Bitcoin block height when the update was created |
| `block_hash` | 32 | Bitcoin block hash at that height |
| `cosignatures` | variable | Sorted list of `CosignEntry` records |
| `operator_signature` | 64 | Schnorr (BIP-340) over content + cosigs |
| `content_hash` | 32 | Computed locally, *not* on the wire |

Look closely at the last row. The TLV encoding does not carry `content_hash` — that field is reconstructed by every receiver via `update.compute_hash()` (`updates.rs:109`). If you build a `SignedLedgerUpdate` by hand and forget to call `compute_hash` after, you will produce a malformed update that fails verification at the first cosign. This catches new contributors regularly enough that there's a memo about it (`feedback_signed_update_content_hash.md`).

A `CosignEntry` is 129 bytes:

    [33 bytes: cosigner_pubkey] [64 bytes: cosign_signature] [32 bytes: member_ledger_hash]

Entries are sorted lexicographically by `cosigner_pubkey` before hashing or signing. Out-of-order entries are signature malleability — same signatures, different hash, different chain. Decoders are required either to reject unsorted input or to canonicalize before verifying.

The wire serialization is TLV (BigSize-prefixed type-length-value, BOLT-1 compatible). The TLV encoder lives in `deposits-protocol/src/tlv.rs`. Each field above gets a tag (type number) and is emitted in sorted order — type 0 first, type 22 last. The whole TLV stream is base64-ed into the content of a Nostr `Kind:9100` event. DEP-02 §"Signed Ledger Update" lists the exact tag numbers.

## The hash chain

The chain hash is what makes a ledger a chain. Every update commits, in its hash, to:

- The whole sequence of prior updates (transitively, through `previous_hash`).
- Its own operation.
- All cosigner signatures for this update.
- The operator's own signature for this update.

The construction is a two-step hash:

    cosig_data = for each entry sorted by pubkey:
        member_ledger_hash || cosign_signature

    content_hash = SHA256(
        sequence_number_le (8 bytes)
        || previous_hash (32 bytes)
        || message (variable)
        || cosig_data
    )

    chain_hash = SHA256(content_hash || operator_signature)

`content_hash` is everything except the operator signature. `chain_hash` folds the operator signature in. The next update sets `previous_hash = chain_hash` of the prior update, which means every signature, by every party, is committed into the chain — without circularity, because the operator signs `content_hash` (which excludes the operator's own signature) and then `chain_hash` is computed from both.

This matters for two reasons. First, equivocation detection: if an operator ever signs two updates with the same `sequence_number` but different `previous_hash` references, both signatures are valid Schnorr signatures and either one is, by itself, a fraud proof. Anyone who has seen both can produce evidence the operator equivocated. Chapter 14 walks through how this gets detected, broadcast, and slashed. Second, replay validity: a fraud-proof verifier can fetch any subset of a ledger's updates from the relay, sort them by sequence, check that each one's `previous_hash` matches the prior update's `chain_hash`, and know it has a contiguous prefix of the operator's signed history. No gaps, no rewrites, no surprises.

The first update in the chain (sequence 0, the `LedgerOpen`) sets `previous_hash = [0; 32]`.

Two more rules about cosignatures and the chain:

1. **After `QuorumBegin`** (the rotation that activates the quorum), every update MUST include at least `floor(n/2) + 1` cosignatures from distinct quorum members. Updates with fewer are non-conforming and rejected by every honest watcher.
2. **Before `QuorumBegin`**, cosig entries are absent except for the very first `QuorumBegin` itself, which carries the majority cosignatures from the members staged via earlier `QuorumAddMember` operations. This is what bootstraps trust into the rotation: the first `QuorumBegin` is non-trivially co-signed even though the prior updates were operator-only.

The legacy single-cosig fields (`cosigner_pubkey`, `cosign_signature`, `member_ledger_hash`) are present in the type for backward-compat with pre-quorum updates but are deprecated. New code should write `cosignatures` and ignore the legacy fields except when reading old data.

## The catalog of operations

The `message` field of a signed update is a TLV-encoded `LedgerOperation`. This enum is *the* protocol surface — it is the catalog of every state transition the protocol supports. It lives in `deposits-protocol/src/messages/types.rs:146`. The first byte of each operation's TLV (tag 0, type discriminant) identifies which variant it is.

The 28 variants group by purpose:

### Lifecycle (2)

- **`LedgerOpen`** (1) — the very first update on a ledger, sequence 0. Carries the operator pubkey, the reserves identifier, the genesis block, the initial reserves amount, and the initial collateral amount. Establishes ledger identity.
- **`LedgerClose`** (60) — terminates the ledger. No further operations may be appended.

### Quorum (4)

- **`QuorumAddMember`** (43) — stage a member into `next_quorum_members`. Records all of the member's terms: minimum fees they require, dispute response timing, max transfer timeouts, compensation rate. Members are added one at a time.
- **`QuorumRemoveMember`** (44) — drop a member from `next_quorum_members` (and from `quorum_members` if active).
- **`QuorumBegin`** (12) — the rotation event. Promotes `next_quorum_members` to `quorum_members`, transitions `quorum_state` from `PreQuorum` to `Active`, points the ledger at a new reserves UTXO (the new Taproot output that the old reserves were swept into), updates `reserves_amount` and `collateral_amount`, and sets `quorum_expiry`. This is the heaviest operation in the protocol — it requires both an on-chain rotation TX and the majority cosignatures bootstrapping into the new quorum.
- **`QuorumJoin`** (46) — appended to the *cosigner's own* ledger when they accept membership in someone else's quorum. Creates a two-sided audit trail: the operator's ledger records `QuorumAddMember`, the member's ledger records `QuorumJoin`. Membership has ratchet semantics: subsequent `QuorumJoin`s for the same `(operator, ledger)` pair can extend `membership_expires` but never shrink it.

### Deposits (4)

- **`DepositOpen`** (20) — open a new deposit. Carries the deposit ID (a 16-byte hash), the miniscript descriptor controlling spending, the maintenance fee schedule, the per-transfer fee schedule, the fee-change governance parameters, and the `receive_requires_sig` flag (whether unsolicited credits are blocked).
- **`DepositClose`** (21) — close a deposit. Refused if its balance is non-zero.
- **`DepositKeyRotate`** (23) — change the miniscript descriptor controlling a deposit. The operation includes a witness satisfying the *old* descriptor, proving the rotation is authorized by the current owner.
- **`FeeCollect`** (50) — collect maintenance fees from a deposit. Reduces the deposit's balance, increases `fees_accumulated`, and (if a `FeeChange` is past its effective block) cuts in the new fee schedule.

### Fees (1)

- **`FeeChange`** (22) — announce a future fee change for a deposit. The new fee schedule is staged with an `effective_block`; it cuts in at the next `FeeCollect` after that block. Must satisfy the deposit's fee-change governance: post-grace period, within the announced bps limit, with the announced notice.

### Lightning (4)

- **`InvoiceCredit`** (30) — credit a deposit with the proceeds of a received Lightning payment. Indexed by `payment_hash` to prevent double-credits.
- **`InvoiceLock`** (31) — lock funds for an outgoing Lightning payment. Carries a witness satisfying the deposit's descriptor.
- **`InvoiceFulfill`** (33) — release the lock with a preimage that hashes to the locked `payment_id`. The successful payment.
- **`InvoiceFail`** (32) — release the lock without a preimage. The payment timed out or failed; the funds return to the deposit minus the fixed portion of the transfer fee.

### On-chain (4)

- **`OnchainCredit`** (35) — credit a deposit with confirmed on-chain funds (a wallet sent BTC to the deposit's funding address).
- **`OnchainLock`** (36) — lock funds for an outgoing on-chain withdrawal. Carries the destination address, the amount, the miner fee, and a descriptor witness.
- **`OnchainFulfill`** (38) — finalize the withdrawal once the spending TX has confirmed.
- **`OnchainFail`** (37) — release the lock; the withdrawal didn't happen. Mirrors `InvoiceFail`.

### Transfers (3)

- **`TransferLock`** (70) — lock funds in a conditional transfer between two deposits on the same ledger. Carries a `nonce` (chosen by the sender; doubles as a fraud-proof embedding slot — see [Chapter 11](11-fraud-proofs.md)), the source and destination deposit IDs, an amount, a fee, a completion script, a timeout height, and a witness satisfying the source descriptor.
- **`TransferComplete`** (71) — close the lock by satisfying its completion script. The amount moves; the fee accrues to `fees_accumulated`.
- **`TransferFail`** (72) — close the lock by timeout. The amount returns to source minus the fixed portion of the transfer fee.

### Dispute (4)

- **`DisputeEnter`** (54) — open a custody dispute. The one operation that may be signed by a key other than the current `parent_pubkey` — specifically, by any pubkey that was a quorum member at the fork point. Snapshots `quorum_at_fork` and transitions `dispute_state` from `Normal` to `Disputed`.
- **`DisputeArmed`** (57) — pre-commit a candidate to the custody lottery. Carries the HASH160 of a secret preimage (the candidate's lottery ticket) and the candidate's target reserves address. Transitions to `Armed`. Multiple candidates each emit their own `DisputeArmed` on their own fork branches.
- **`DisputeAcquire`** (55) — record that this candidate won the on-chain lottery. Carries the new custodian pubkey, the on-chain claim TXID, and the new reserves address. Transitions back to `Normal` with a new operator. The lottery winner-selection is enforced by the on-chain Tapscript, not by the state machine — `DisputeAcquire` just records what the chain proved.
- **`DisputeYield`** (56) — record that this candidate did not win. Transitions to `Tombstoned`. No further operations on this branch.

### Delivery (1)

- **`DeliveryEmbed`** (80) — appended by a quorum member to *their own* ledger when a wallet escalates an unprocessed request. Records the SHA256 of the wallet's signed request payload, the target ledger ID, and the target operator. Starts the `service_response_blocks` clock; if the operator doesn't respond within that window the request becomes fraud-proof evidence. Covered in [Chapter 15](15-delivery-escalation.md).

### Quick orientation

Reads of `LedgerOperation::discriminant()` (`messages/types.rs:529`) tell you the encoded byte. Reads of `LedgerState::apply` (`ledger_state.rs:195`) tell you the state transition each variant produces. The full TLV field maps for each operation are in DEP-02 §"Operation TLV Fields"; the appendix [Appendix B: Wire Format Reference](appendix-b-wire-format.md) reproduces them in book form.

## The state machine

A ledger's state — the thing that grows as updates are applied — is `LedgerState` in `deposits-protocol/src/types/ledger_state.rs:25`. Its fields fall into four groups:

**Identity and chain**

- `ledger_id`, `genesis_block` — the immutable identity from `LedgerOpen`.
- `operator_key`, `reserves_key`, `reserves_outpoint` — the current operator and their reserves anchor. `operator_key` rotates on `DisputeAcquire`; `reserves_key` rotates on `QuorumBegin`.
- `sequence`, `chain_tip_hash` — current position in the chain.

**Money**

- `deposits: HashMap<DepositId, Deposit>` — every deposit on this ledger. Each carries `balance`, `locked_balance`, `descriptor`, fee schedules, fee-change governance, and accounting timestamps.
- `reserves_amount` — the deposit capacity of the reserves UTXO. Total deposit balance must never exceed this.
- `collateral_amount` — the operator's bond. Forfeited on losing a custody dispute. Deposits cannot back against it.
- `pending_transfers`, `open_invoice_locks`, `pending_withdrawals` — in-flight operations awaiting completion or timeout.
- `credited_payments` — payment hashes that have already been credited; prevents double-credits.
- `fees_accumulated` — running total of operator-side fee revenue, the substrate for member compensation payouts.

**Quorum**

- `quorum_state: QuorumState` — `PreQuorum`, `Active`, or `Expired`.
- `quorum_members`, `next_quorum_members` — the active set and the staged-for-next-rotation set.
- `quorum_expiry` — block height at which the active quorum's commitment ends. A new `QuorumBegin` must land before this height or the chain becomes non-conforming.
- `joined_quorums` — the inverse view: quorums *this* ledger's operator has joined as a member of someone else's ledger.

**Dispute**

- `dispute_state: DisputeState` — `Normal`, `Disputed`, `Armed`, or `Tombstoned`.
- `parent_pubkey` — the pubkey that signed the most recent update. All subsequent updates must be signed by this same pubkey, with the singular exception of `DisputeEnter`.
- `quorum_at_fork`, `dispute_fork_sequence` — snapshot of the active quorum and sequence number at the moment a dispute was entered. Used to verify that disputants were actually members at the fork point.

State transitions are pure functions: `LedgerState::apply(operation) -> LedgerState`. Same prior state plus same operation always produces the same result, no I/O, no randomness. This is the cornerstone of fraud-proof verification: a verifier can fetch a ledger's signed updates from the relay, replay them through `apply` from sequence 0, and produce the *exact* `LedgerState` the operator and members had after each update. Disagreement implies a bug, an equivocation, or a non-conforming update.

The dispute state machine is a small additional restriction on top of the operation enum: each `DisputeState` value names which discriminants are legal next operations. `DisputeState::allows_operation` (`types/core.rs:707`) is the source of truth. In `Normal`, every operation except the dispute-acquire pair is allowed. In `Disputed`, only `QuorumAddMember` and `DisputeArmed`. In `Armed`, only `DisputeAcquire` or `DisputeYield`. In `Tombstoned`, none. These rules show up at the validation layer and prevent, for example, an operator from quietly minting a `DepositOpen` after a dispute has been entered.

## Conformance: more than just `apply`

`apply` checks the basic structural rules — does the deposit exist, is the source's available balance sufficient, has the payment hash already been credited. It does *not* check everything that makes an operation conforming. The richer check is `LedgerState::check_conformance` (`ledger_state.rs:680`), and the operator-facing wrapper that ties them together is `Ledger::checked_apply` (`deposits-core/src/ledger.rs:1369`).

The conformance pass adds:

- **Reserve sufficiency.** After any credit (`InvoiceCredit`, `OnchainCredit`, `TransferComplete`), `total_deposit_balance() <= reserves_amount` must hold. Over-promising — accepting more deposits than the reserves UTXO can pay out — is the canonical operator misbehavior.
- **Witness verification.** Every operation that carries a descriptor witness (`InvoiceLock`, `InvoiceFulfill`, `OnchainLock`, `TransferLock`, `DepositKeyRotate`) is checked against the deposit's miniscript descriptor. The witness must satisfy the descriptor over the canonical signing message for the operation. For `DepositKeyRotate`, the witness must satisfy the *old* descriptor (proving authorization to rotate); for the others, the *current* descriptor suffices.
- **Preimage match.** `InvoiceFulfill` checks that `SHA256(preimage) == payment_id`. A preimage that doesn't match the locked payment hash is non-conforming.

There are also pre-commit validation checks layered above this in `Ledger::validate_operation` (`ledger.rs:1219`): the dispute state must allow the operation discriminant, the quorum-size policy (`Q ∈ VALID_QUORUM_SIZES = {3, 5, 7}`, where `Q` is the cosigner count and the operator is not included), `DepositClose` requires zero balance, `QuorumJoin` requires the operator role and ratchet-monotonic expiration, `DisputeAcquire` requires a non-zero `claim_txid`. And in `stage_operation`, fee-change operations are validated against the deposit's fee-change governance (`operation_validation::validate_deposit_fee_change`).

When any of these checks fail, the operator's path returns `DepositsError::ProtocolViolation` and the operation is refused — a well-behaved operator can never produce a non-conforming chain. The watcher path takes the alternative `apply_and_check`, which applies the operation and returns a `Vec<ConformanceViolation>` so the watcher can keep tracking a misbehaving operator and assemble a fraud proof. The full enumeration of error codes and conformance violations is in [Appendix C](appendix-c-error-codes.md).

## Two-phase commit: stage, then sign, then commit

Operators don't apply operations to their ledger directly. They use a two-phase commit pattern:

1. **`stage_operation(op, block_height, block_hash)`** — `deposits-core/src/ledger.rs:1035`. Validates the operation against current state, builds a `SignedLedgerUpdate` with `operator_signature` zeroed and `cosignatures` empty, returns a `StagedUpdate { operation, update }`. **The ledger state is not changed.** If validation fails here, the operator hasn't committed to anything yet.
2. **(off-stage)** — the operator collects cosignatures from a majority of quorum members, then signs themselves. Both signing data constructions are in DEP-02 §"Signing"; cosigners sign a tagged hash over `(sequence || prev_hash || message || member_ledger_hash)`, the operator signs over `(cosign_data || all_cosig_signatures)`. The operator updates the staged update in place, calling `apply_majority_cosignatures` (which recomputes `content_hash`) and then setting `operator_signature`.
3. **`commit_staged(staged)`** — `ledger.rs:1107`. Verifies the staged update's `previous_hash` still matches the chain tip (no race), verifies the operator signature is non-zero, calls `checked_apply` to advance state, sets `chain_tip_hash = staged.update.chain_hash()`, pushes to history.

Why this structure? Because the operator must validate before signing and sign before applying.

If the operator applied first, then signed, a non-conforming operation would briefly become the ledger state — and any race with another in-flight commit would corrupt the chain. By keeping `stage` read-only, the operator can validate, fail loudly, abort, and the ledger is unchanged.

If the operator signed before validating, they could sign a non-conforming update and broadcast it before realizing — at which point cosigners would refuse, the update would be unsignable, and the operator would have a dangling signature that committed them to nothing useful. Worse: if the operator signed a non-conforming update and fed it into the chain locally, they would be the author of fraud-proof evidence against themselves.

The staging pattern keeps validation, signing, and application as three distinct steps with explicit transitions between them. The reference daemon's actor model (Chapter 20) takes this further by funneling all stage-and-commit calls for a given ledger through a single tokio task that owns the `Arc<RwLock<Ledger>>` — there is exactly one writer per ledger, ever.

## Where this leads

A ledger anchors to one Bitcoin UTXO, and the rules governing that UTXO are what make the collateral structure load-bearing. [Chapter 5](05-onchain-transactions.md) opens up the Taproot script tree: how the reserves UTXO is structured, what spend paths exist (cooperative rotation, dispute-armed lottery, fallback timeouts), and why the on-chain layer can enforce the protocol's economic rules without an L1 consensus change.
