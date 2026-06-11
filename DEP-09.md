# DEP-09: Transfers

## Abstract

This document specifies the two-phase transfer protocol between deposits on the same ledger. A transfer locks funds with a miniscript spending condition; if the condition is satisfied before a timeout, funds move to the recipient minus the operator's fee. If the timeout is reached, funds are returned to the sender minus a smaller fee.

## Transfer Protocol

### Phase 1: Lock (disc 70)

The sender requests a `TransferLock` with:

- **nonce**: 32 random bytes (also used for fraud proof embedding -- see DEP-06)
- **source_deposit_id**: the sender's deposit
- **destination_deposit_id**: the recipient's deposit
- **amount**: amount to transfer (msats)
- **fee**: operator's transfer fee (msats, must match the deposit's TransferFeeSchedule)
- **completion_script**: miniscript condition the recipient must satisfy
- **timeout_height**: block height after which the transfer can be failed. Must not exceed `block_height + max_transfer_timeout_blocks` (see below)
- **transfer_id**: 32-byte identifier (derived from the signing message hash)
- **witness**: satisfies the sender's deposit descriptor, authorizing the lock

The operator verifies the sender's witness, checks sufficient balance, validates the fee, and appends the operation. The source deposit's `locked_balance` is increased by `amount + fee`, earmarking that portion of `balance` for the pending transfer. The `balance` itself is unchanged until the transfer is settled (see DEP-05 for the balance accounting model).

If the destination deposit has `receive_requires_sig`, the request must also include a `receive_signature` from the destination descriptor.

### Phase 2a: Complete (disc 71)

The recipient (or anyone who can satisfy the completion_script) provides a `TransferComplete` with:

- **transfer_id**: matches the lock
- **script_witness**: satisfies the `completion_script` from the lock

**Enforcement.** Verifiers (cosigners and replayers) evaluate `script_witness` against the lock's `completion_script` through the dep-16 evaluator: the witness stack's entries are bound to the descriptor's obligations by content — 64-byte entries tried as ECDSA signatures over the dep-17 operation preimage, any-length entries tried as hash preimages (re-hashed against each `hashlock` target), 32-byte entries tried as scalars (curve-checked against each `pointlock` target). A `TransferComplete` whose witness fails evaluation is non-conforming; cosigners refuse it and replayers flag it. This is a hard validity rule — a release with a wrong preimage or scalar cannot commit.

On success: `amount` is credited to the destination deposit, `fee` is credited to the operator, and the transfer is removed from pending.

### Phase 2b: Fail (disc 72)

If the timeout is reached without completion, the operator appends `TransferFail` with:

- **transfer_id**: matches the lock
- **block_hash**: the block hash at timeout height
- **reason**: failure reason (1 = timeout, 0 = reserved)

On failure: the lock on the source (`amount + fee`) is released; the source recovers `amount + proportional_portion_of_fee`, and the **fixed** portion of the fee (`fixed_msats` from the source's `TransferFeeSchedule`) is charged to the source's balance and credited to the operator. The transfer is removed from pending. See DEP-07 §"Fee on Failure" for the full model.

## Completion Scripts

The `completion_script` is a dep-16 descriptor (see DEP-16 for the full language) that determines how the transfer can be completed. Common patterns:

- **HTLC**: `sha256(H)` — recipient provides the preimage. This is the basis for cross-ledger and lightning-compatible transfers.
- **PTLC**: `pointlock(P)` — recipient provides a scalar `s` with `G·s == P`. The privacy-preserving variant used by the courier protocol's PTLC pattern (DEP-13 §"Courier PTLC pattern"). Requires the operator to advertise `pointlock` in their capability set (DEP-16 §capability) — operators that don't refuse such descriptors at admission.
- **Signature**: `pk(recipient_key)` — recipient signs the transfer_id.
- **Timelock**: `and(pk(key), after(N))` — key + minimum block height.
- **Multi-party**: `multi(2, key1, key2)` — requires multiple signers.

Any descriptor admitted by the operator's capability set is supported. The witness must discharge every proof obligation in the script.

## Fee Validation

The transfer fee must exactly match the source deposit's `TransferFeeSchedule`:

    expected_fee = fixed_msats + (amount_msats * rate_bps / 10000)

The operator rejects transfers with mismatched fees.

## Transfer ID

The transfer_id is derived deterministically from the lock signing message:

    signing_message = transfer_lock_signing_message(nonce, src, dst, amount, fee, script, timeout)
    transfer_id = SHA256(signing_message)

This ensures uniqueness and allows the sender to compute the transfer_id before submitting.

## State Machine

```
Lock → [pending_transfers]
  ├─ Complete → funds to recipient, fee to operator
  └─ Fail (timeout) → funds to sender (minus timeout fee)
```

A pending transfer occupies `locked_balance` on the source deposit until resolved.

## Transfer Timeout Limits

The `timeout_height` must not be more than `max_transfer_timeout_blocks` beyond the current `block_height`. This prevents an attacker from locking funds with an unreasonably distant timeout, effectively freezing the sender's balance. `max_transfer_timeout_blocks` is a per-quorum parameter recorded in `QuorumAddMember` (default: 1008 blocks, ~1 week). The operator rejects `TransferLock` requests that exceed this limit.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (TransferLock, TransferComplete, TransferFail fields)
- [DEP-07](DEP-07.md): Fee schedules (TransferFeeSchedule)
- [DEP-08](DEP-08.md): Deposits (descriptor witnesses, receive_requires_sig)
- [DEP-13](DEP-13.md): Couriers (cross-ledger transfers via HTLC or PTLC intermediaries)
- [DEP-16](DEP-16.md): Descriptor language (the grammar `completion_script` is written in)
