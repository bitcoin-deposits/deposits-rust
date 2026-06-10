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
- **receive_requires_sig**: if true, incoming transfers, offers, and invoices require a witness from the deposit's descriptor
- **fee_change_after_blocks**: blocks after opening before fees can change (see DEP-07)
- **fee_change_notice_blocks**: blocks of notice before a fee change takes effect
- **fee_change_limit_bps**: maximum fee change per adjustment

The serialized descriptor must not exceed the quorum's `max_descriptor_bytes` limit (see DEP-05). If no quorum is established, the operator's own advertised limit applies. Operators advertise their descriptor size limit in their Kind 39100 advertisement.

The deposit starts with zero balance. Funds are added via on-chain offers, lightning invoices, or transfers from other deposits (see DEP-10, DEP-09).

### Close (disc 21)

`DepositClose` removes the deposit. The deposit must have zero `balance` and no in-flight operations (`locked_balance == 0`).

### Key Rotation (disc 23)

`DepositKeyRotate` changes the deposit's descriptor while preserving its `deposit_id`. The request must include a witness satisfying the current descriptor, proving the current owner authorized the rotation. The `new_descriptor` replaces the current one.

## Witness Verification

All deposit operations are authorized by providing a `DescriptorWitness` — a keyed bundle of signatures, preimages, scalars, and attestations that discharges the deposit descriptor's proof obligations against the operation's canonical signing message (DEP-17).

For `pk()` descriptors, the witness is a single 64-byte Schnorr signature. Richer descriptors discharge multiple obligations: `hashlock` consumes a preimage, `pointlock` (DEP-16 §obligations, used by the PTLC courier pattern in DEP-13) consumes a 32-byte scalar `s` with `G·s == P`, `attest` consumes an oracle attestation. See DEP-16 §evaluation for the full evaluator semantics.

Verification:
1. If the descriptor is `pk(<hex>)`, fast path: verify the single Schnorr signature against the pubkey.
2. Otherwise, evaluate the descriptor under DEP-16: each proof obligation is discharged by the witness entry under the appropriate key. Operators that haven't advertised a given obligation kind in their capability set refuse such descriptors at admission rather than at spend time.

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

## Access Control

Operators MAY restrict which pubkeys can open deposits. When enabled, deposit_open requests are evaluated in order:

1. **Denylist**: always checked. Matching pubkeys are rejected unconditionally.
2. **Pubkey allowlist**: if the sender's pubkey is listed, the deposit is allowed.
3. **Domain attestation**: the operator queries relays for a Kind 55502 attestation (see DEP-04) from a trusted verifier, tagged with the sender's pubkey. If found, the lightning address domain is checked against an allowed domains list.

If none of the above permit the deposit, the operator responds with an error containing:

```json
{
  "code": "attestation_required",
  "verifier_pubkey": "<hex>",
  "allowed_domains": ["domain1.com", "domain2.com"]
}
```

The wallet then initiates verification with the indicated verifier (Kind 25500/25501 exchange).

The operator's verifier pubkey (`ATTESTATION_VERIFIER_PUBKEY`) accepts both hex and npub bech32 formats; it is normalized to hex at load time.

## Deposit Recovery

Wallets can recover deposits from relays using only their seed. The procedure:

1. Derive compressed pubkeys at key indices 0 through N (at least 20).
2. Compute `deposit_id = SHA256("pk(<compressed_pubkey_hex>)")[0..16]` for each.
3. Query relays for Kind 9100 events with matching `#i` tags.
4. For each match, decode the TLV content and extract the full 64-character ledger ID from field tag 2 (LEDGER_ID).
5. Look up the operator name from the Kind 39100 advertisement for that ledger.
6. Add the deposit to local state and fetch its balance via `balance_query`.

This allows wallet restoration from seed alone, without requiring a remote state backup.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DepositOpen, DepositClose, DepositKeyRotate fields)
- [DEP-04](DEP-04.md): Peer messaging (domain attestation, subkey management, verification protocol)
- [DEP-05](DEP-05.md): Quorum and collateral (collateral declared at LedgerOpen, obligation limits)
- [DEP-07](DEP-07.md): Fee schedules (periodic and transfer fees, fee changes)
- [DEP-09](DEP-09.md): Transfers (two-phase transfer protocol)
- [DEP-10](DEP-10.md): Payment channels (on-chain and lightning funding)
- [DEP-12](DEP-12.md): Certified delivery (escalation for unprocessed deposit operations)
- [DEP-16](DEP-16.md): Descriptor language (the calculus deposit witnesses discharge)
- [DEP-17](DEP-17.md): Canonical encodings (operation preimage, descriptor commitment, witness encoding)
