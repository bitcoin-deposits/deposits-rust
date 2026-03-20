# DEP-08: Deposits

## Abstract

This document specifies the deposit lifecycle: how accounts are created, controlled, and closed on a Bitcoin Deposits ledger. A deposit is a balance controlled by a miniscript descriptor. The operator maintains the balance; the descriptor owner authorizes operations by providing a satisfying witness.

## Deposit Identity

A deposit is identified by a 16-byte `deposit_id`, derived from its descriptor:

    deposit_id = SHA256(descriptor)[0..16]

The descriptor is a miniscript policy string. The most common case is `pk(<compressed_pubkey_hex>)` for single-key deposits, but any valid miniscript is supported: `multi(k, key1, key2, ...)`, `and(pk(A), after(N))`, `or(pk(A), and(pk(B), sha256(H)))`, etc.

## Lifecycle

### Open (disc 20)

A deposit is created with `DepositOpen`, which establishes:

- **descriptor**: the miniscript spending policy
- **fees**: periodic custody fee schedule (see DEP-07)
- **transfer_fees**: per-transfer fee schedule (see DEP-07)
- **is_collateral**: if true, this deposit is subject to collateral rules (see DEP-05) and cannot be transferred or withdrawn normally
- **receive_requires_sig**: if true, incoming transfers, offers, and invoices require a witness from the deposit's descriptor
- **fee_change_after_blocks**: blocks after opening before fees can change (see DEP-07)
- **fee_change_notice_blocks**: blocks of notice before a fee change takes effect
- **fee_change_limit_bps**: maximum fee change per adjustment

The serialized descriptor must not exceed the quorum's `max_descriptor_bytes` limit (see DEP-05). If no quorum is established, the operator's own advertised limit applies. Operators advertise their descriptor size limit in their Kind 39100 advertisement.

The deposit starts with zero balance. Funds are added via on-chain offers, lightning invoices, or transfers from other deposits (see DEP-10, DEP-09).

### Close (disc 21)

`DepositClose` removes the deposit. The deposit must have zero balance and zero locked balance.

### Key Rotation (disc 23)

`DepositKeyRotate` changes the deposit's descriptor while preserving its `deposit_id`. The request must include a witness satisfying the current descriptor, proving the current owner authorized the rotation. The `new_descriptor` replaces the current one.

## Witness Verification

All deposit operations are authorized by providing a `DescriptorWitness` — a stack of byte arrays that satisfies the deposit's miniscript descriptor against a message hash.

For `pk()` descriptors, the witness is a single 64-byte Schnorr signature. For more complex descriptors, the witness contains multiple signatures and/or preimages as required by the policy.

Verification:
1. If the descriptor is `pk(<hex>)`, fast path: verify the single Schnorr signature against the pubkey
2. Otherwise, parse the descriptor as miniscript, extract keys, verify each signature in the witness stack

The message hash varies by operation:
- **Transfer lock**: `transfer_lock_signing_message(nonce, src, dst, amount, fee, script, timeout)`
- **Withdrawal**: `withdrawal_signing_message(nonce, deposit_id, address, amount, fee)`
- **Key rotation**: `SHA256(new_descriptor)`
- **Receive authorization**: the `transfer_id` (for transfers) or zero-padded `deposit_id` (for offers/invoices)

## Receive Authorization

When `receive_requires_sig` is true, the operator must verify a witness from the destination deposit's descriptor before:
- Creating an on-chain funding offer
- Creating a lightning invoice
- Accepting an incoming transfer

This prevents unsolicited crediting and gives the deposit owner control over what enters the account.

## Collateral Deposits

When `is_collateral` is true:
- The deposit is subject to `CollateralLock` operations (see DEP-05)
- Normal transfers and withdrawals are restricted
- The deposit holds operator capital on a quorum member's ledger, backing the operator's obligations elsewhere
- If the operator misbehaves, the member operating this ledger may confiscate the locked funds

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DepositOpen, DepositClose, DepositKeyRotate fields)
- [DEP-05](DEP-05.md): Quorum and collateral (collateral deposits, obligation limits)
- [DEP-07](DEP-07.md): Fee schedules (periodic and transfer fees, fee changes)
- [DEP-09](DEP-09.md): Transfers (two-phase transfer protocol)
- [DEP-10](DEP-10.md): Payment channels (on-chain and lightning funding)
- [DEP-12](DEP-12.md): Certified delivery (escalation for unprocessed deposit operations)
