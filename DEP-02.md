# DEP-02: Ledger State Model

## Abstract

This document specifies the wire format, hash chain structure, and signing protocol for Bitcoin Deposits ledger updates. A ledger is an append-only chain of signed updates, cooperatively maintained by an operator and a quorum of co-signing members.

## Notation

- All multi-byte integers are big-endian unless stated otherwise
- `||` denotes concatenation
- `SHA256()` is the SHA-256 hash function
- `[N]` denotes a fixed-length byte array of N bytes
- Amounts are in millisatoshis unless stated otherwise

## TLV Encoding

All structures use Type-Length-Value encoding with BigSize varints, compatible with the Lightning Network TLV format (BOLT #1).

### BigSize

| Value Range | Encoding |
|---|---|
| 0x00..0xfc | 1 byte |
| 0xfd..0xffff | 0xfd followed by 2 bytes |
| 0x10000..0xffffffff | 0xfe followed by 4 bytes |
| 0x100000000..0xffffffffffffffff | 0xff followed by 8 bytes |

### TLV Record

    [BigSize: type] [BigSize: length] [length bytes: value]

Records are ordered by type number. Even types are required; odd types are optional and may be ignored by parsers that don't understand them.

## Signed Ledger Update

The event content is a base64-encoded TLV stream:

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | message | variable | Inner operation (TLV-encoded) |
| 2 | message_type | 2 | Protocol message type constant |
| 4 | operator_id | 33 | Operator's compressed secp256k1 pubkey |
| 6 | ledger_id | 32 | Ledger identifier hash |
| 8 | sequence_number | 8 | Monotonically increasing sequence (u64 LE) |
| 10 | previous_hash | 32 | Chain hash of the previous update |
| 16 | cosign_signature | 64 | Schnorr co-signature from quorum member |
| 18 | operator_signature | 64 | Schnorr signature from operator |
| 20 | block_height | 4 | Block height at creation (optional) |
| 22 | block_hash | 32 | Block hash at creation (optional) |
| 24 | cosigner_pubkey | 33 | Co-signing quorum member's pubkey (optional) |
| 26 | member_ledger_hash | 32 | Co-signer's ledger tip hash (optional) |

Type 12 is reserved. `current_hash` is derived by the receiver (see Hash Chain).

## Hash Chain

    current_hash = SHA256(
        sequence_number (8 bytes LE)
        || previous_hash (32 bytes)
        || message (variable)
        [|| member_ledger_hash (32 bytes)]
        [|| cosign_signature (64 bytes)]
    )

    chain_hash = SHA256(current_hash (32 bytes) || operator_signature (64 bytes))

The operator signs `current_hash`. Their signature is folded into `chain_hash`, which becomes the next update's `previous_hash`. Both signatures are committed to the chain without circularity.

Optional fields (`member_ledger_hash`, `cosign_signature`) are included in `current_hash` only when present and non-zero. The first update (sequence 0) has `previous_hash` = `[0; 32]`.

## Signing

All protocol signatures use Schnorr (BIP-340). On-chain transaction signatures follow bitcoin consensus rules separately.

### Co-signing

The quorum member signs a tagged hash over the update content and their ledger's tip:

    tag = SHA256("deposits/cosign")
    digest = SHA256(tag || tag || message || message_type (2 LE) || sequence_number (8 LE) || previous_hash || member_ledger_hash)

`current_hash` is not signed directly -- it incorporates the co-signature itself, so it cannot be known at signing time.

### Operator

    sig_input = SHA256(sequence_number (8 LE) || previous_hash || current_hash || message)

The operator signs `sig_input` after `current_hash` is finalized (which requires the co-signature).

## Operations

The `message` field contains a TLV-encoded operation. Type 0 is always a 1-byte discriminant.

### Discriminants

| Disc | Operation | Category |
|---|---|---|
| 1 | LedgerOpen | Lifecycle |
| 60 | LedgerClose | Lifecycle |
| 10 | ReservesIncrease | Reserves |
| 11 | ReservesDecrease | Reserves |
| 12 | ReservesRotate | Reserves |
| 20 | DepositOpen | Deposits |
| 21 | DepositClose | Deposits |
| 22 | FeeChange | Deposits |
| 23 | DepositKeyRotate | Deposits |
| 30 | InvoiceCredit | Lightning |
| 31 | InvoiceLock | Lightning |
| 32 | InvoiceFail | Lightning |
| 33 | InvoiceFulfill | Lightning |
| 35 | OnchainCredit | On-chain |
| 36 | OnchainLock | On-chain |
| 37 | OnchainFail | On-chain |
| 38 | OnchainFulfill | On-chain |
| 40 | CollateralIncrease | Collateral |
| 41 | CollateralDecrease | Collateral |
| 42 | CollateralAttestation | Collateral |
| 43 | QuorumAddMember | Quorum |
| 44 | QuorumRemoveMember | Quorum |
| 45 | CollateralLock | Collateral |
| 46 | QuorumJoin | Quorum |
| 50 | FeeCollect | Fees |
| 54 | CustodyDispute | Recovery |
| 55 | CustodyAcquire | Recovery |
| 56 | CustodyYield | Recovery |
| 57 | CustodyArmed | Recovery |
| 70 | TransferLock | Transfers |
| 71 | TransferComplete | Transfers |
| 72 | TransferTimeout | Transfers |

### Operation TLV Fields

#### Common

| Type | Name | Size |
|---|---|---|
| 0 | discriminant | 1 |
| 2 | amount | 8 |
| 36 | block_height | 4 |

#### Ledger and Reserves

| Type | Name | Size | Used by |
|---|---|---|---|
| 6 | quorum_members | N*33 | ReservesRotate |
| 8 | new_amount | 8 | ReservesIncrease, ReservesDecrease |
| 56 | operator_id | 33 | LedgerOpen |
| 58 | reserves_id | variable | LedgerOpen, ReservesIncrease, ReservesDecrease, ReservesRotate, QuorumJoin |
| 60 | ledger_address | variable | LedgerOpen |
| 96 | genesis_block | 4 | LedgerOpen |

#### Deposits

| Type | Name | Size | Used by |
|---|---|---|---|
| 200 | deposit_id | 16 | DepositOpen, DepositClose, FeeChange, DepositKeyRotate, FeeCollect |
| 202 | descriptor | variable | DepositOpen |
| 208 | new_descriptor | variable | DepositKeyRotate |
| 229 | is_collateral | 1 | DepositOpen (odd, optional) |
| 231 | receive_requires_sig | 1 | DepositOpen (odd, optional) |

#### Fees

| Type | Name | Size | Used by |
|---|---|---|---|
| 12 | fees | variable | DepositOpen (nested FeeStructure) |
| 20 | new_fees | variable | FeeChange (nested FeeStructure) |
| 226 | transfer_fees | variable | DepositOpen (nested TransferFeeSchedule) |
| 243 | fee_change_after_blocks | 4 | DepositOpen (odd, optional) |
| 245 | fee_change_notice_blocks | 4 | DepositOpen (odd, optional) |
| 247 | fee_change_limit_bps | 2 | DepositOpen (odd, optional) |
| 249 | effective_block | 4 | FeeChange (odd, optional) |

#### Transfers

| Type | Name | Size | Used by |
|---|---|---|---|
| 210 | nonce | 32 | TransferLock |
| 212 | source_deposit_id | 16 | TransferLock |
| 214 | destination_deposit_id | 16 | TransferLock |
| 216 | completion_script | variable | TransferLock |
| 218 | timeout_height | 4 | TransferLock |
| 220 | transfer_id | 32 | TransferLock, TransferComplete, TransferTimeout |
| 204 | witness | variable | TransferLock, DepositKeyRotate (nested) |
| 224 | script_witness | variable | TransferComplete (nested) |

#### Lightning and On-chain

| Type | Name | Size | Used by |
|---|---|---|---|
| 14 | payment_hash | 32 | InvoiceCredit, InvoiceLock, InvoiceFulfill |
| 16 | invoice | variable | DepositOpen (BOLT11 string) |
| 26 | invoice_id | variable | InvoiceCredit |
| 66 | txid | 32 | OnchainCredit, OnchainFulfill |
| 68 | vout | 4 | OnchainCredit |
| 70 | destination_address | variable | OnchainLock, OnchainFulfill |
| 72 | withdrawal_id | 32 | OnchainLock, OnchainFail, OnchainFulfill |

#### Quorum and Collateral

| Type | Name | Size | Used by |
|---|---|---|---|
| 44 | quorum_member | 33 | QuorumAddMember, QuorumRemoveMember, CollateralAttestation |
| 38 | collateral_operator | 33 | CollateralAttestation |
| 76 | lock_until_block | 4 | CollateralLock, CollateralAttestation |
| 114 | member_ledger_id | variable | QuorumAddMember, QuorumJoin |
| 115 | collateral_ledger_id | variable | CollateralAttestation |
| 233 | min_fee_bps | 2 | QuorumAddMember (odd, optional) |
| 235 | min_fee_fixed | 8 | QuorumAddMember (odd, optional) |
| 237 | max_fee_period | 4 | QuorumAddMember (odd, optional) |
| 239 | collateral_lock_amount | 8 | QuorumAddMember (odd, optional) |
| 241 | collateral_lock_until | 4 | QuorumAddMember (odd, optional) |

### Nested TLV: FeeStructure

| Type | Name | Size |
|---|---|---|
| 0 | annualized_fixed | 8 |
| 2 | annualized_bps | 2 |
| 4 | frequency_blocks | 4 |

### Nested TLV: TransferFeeSchedule

| Type | Name | Size |
|---|---|---|
| 0 | fixed_sats | 8 |
| 2 | rate_bps | 2 |

## Related DEPs

- [DEP-03](DEP-03.md): On-chain transaction formats
- [DEP-04](DEP-04.md): Peer messaging
- [DEP-05](DEP-05.md): Quorum and collateral
- [DEP-06](DEP-06.md): Fraud proofs and recovery
- [DEP-07](DEP-07.md): Fee schedules

## References

- [BOLT #1](https://github.com/lightning/bolts/blob/master/01-messaging.md) -- TLV encoding
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) -- Schnorr signatures, tagged hashing
