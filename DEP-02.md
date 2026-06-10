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

Records are ordered by type number. All current field types are even. Odd types are reserved for future forward-compatible extensions that unknown implementations may safely ignore.

## Signed Ledger Update

The event content is a base64-encoded TLV stream:

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | operator_id | 33 | Operator's compressed secp256k1 pubkey |
| 2 | ledger_id | 32 | Ledger identifier hash |
| 4 | sequence_number | 8 | Monotonically increasing sequence (u64 BE) |
| 6 | previous_hash | 32 | Chain hash of the previous update |
| 8 | message | variable | Inner operation (TLV-encoded) |
| 10 | block_height | 4 | Block height at creation |
| 12 | block_hash | 32 | Block hash at creation |
| 14 | cosigner_pubkey | 33 | *Deprecated*. Single co-signer pubkey (pre-majority format). |
| 16 | member_ledger_hash | 32 | *Deprecated*. Single co-signer's ledger hash (pre-majority format). |
| 18 | cosign_signature | 64 | *Deprecated*. Single co-signature (pre-majority format). |
| 20 | operator_signature | 64 | Schnorr signature from operator |
| 22 | cosignatures | variable | Majority cosignature list (see Cosignatures below) |

`current_hash` is derived by the receiver (see Hash Chain).

### Cosignatures (Tag 22)

Tag 22 contains one or more cosignature entries concatenated as length-prefixed records. Each entry is:

    [u16 BE: entry_length] [entry_length bytes: cosig_entry]

Each `cosig_entry` is:

| Offset | Size | Field |
|---|---|---|
| 0 | 33 | cosigner_pubkey (compressed secp256k1) |
| 33 | 64 | cosign_signature (Schnorr BIP-340) |
| 97 | 32 | member_ledger_hash (cosigner's ledger tip) |

Total entry size: 129 bytes. Entries MUST be sorted by cosigner_pubkey (lexicographic on serialized bytes). This ensures deterministic hashing. Decoders MUST either reject unsorted input or canonicalize it before verifying `current_hash` and the operator signature — otherwise a malicious sender can reorder entries to produce a distinct but otherwise-valid hash for the same logical cosignature set, enabling signature malleability.

After `QuorumBegin`, updates MUST carry the cosignature threshold specified in DEP-05 §Lifecycle for the operation's class and the lifecycle tier at the update's `block_height`. Within the active period (`block_height < quorum_expiry`) this resolves to `floor(n/2) + 1` cosignatures from distinct quorum members (where n is the quorum size) — strict majority — for every operation. Past `quorum_expiry`, only establishment operations (`QuorumAddMember`, `QuorumRemoveMember`, `QuorumBegin`) remain cosignable and their required threshold cascades through the tiers in DEP-05 §Lifecycle; updates carrying any other op type past `quorum_expiry` are non-conforming regardless of cosignature count.

For backward compatibility, decoders SHOULD accept the deprecated single-cosig format (tags 14/16/18) from pre-quorum updates and upgrades in progress.

## Hash Chain

    cosig_data = for each cosig entry (sorted by pubkey):
        member_ledger_hash || cosign_signature

    current_hash = SHA256(
        sequence_number (8 bytes LE)
        || previous_hash (32 bytes)
        || message (variable)
        || cosig_data (variable, all entries concatenated)
    )

    chain_hash = SHA256(current_hash (32 bytes) || operator_signature (64 bytes))

The operator signs the content and all co-signatures (see Signing). Their signature is folded into `chain_hash`, which becomes the next update's `previous_hash`. All signatures are committed to the chain without circularity.

After `QuorumBegin`, the cosig entries are mandatory at whatever threshold DEP-05 §Lifecycle prescribes for the operation type and tier — omitting them entirely, or providing fewer than the prescribed count, is non-conforming. Before quorum establishment, cosig entries are omitted on all updates **except the first `QuorumBegin`**, which MUST carry cosignatures from `floor(n/2) + 1` of the members staged via prior `QuorumAddMember` operations (n = `len(next_quorum_members)` at the point the update is applied). Decoders MUST reject a first `QuorumBegin` that lacks this majority. Without the rule, the operator could unilaterally transition to Active with a fabricated member list or a reserves outpoint that doesn't actually exist on-chain. See DEP-05 §QuorumBegin for the full rule and DEP-03 §QuorumBegin for the on-chain verification obligation cosigners must discharge before signing.

The first update (sequence 0) has `previous_hash` = `[0; 32]`.

## Signing

All protocol signatures use Schnorr (BIP-340). On-chain transaction signatures follow bitcoin consensus rules separately.

### Co-signing

Each quorum member independently signs a tagged hash over the update content and their own ledger's tip:

    tag = SHA256("deposits/cosign")
    cosign_data = sequence_number (8 LE) || previous_hash || message
    digest = SHA256(tag || tag || cosign_data || member_ledger_hash)

`current_hash` is not signed directly — it incorporates the co-signatures themselves, so it cannot be known at signing time.

The operator collects the threshold of co-signatures specified in DEP-05 §Lifecycle (within the active period this is `floor(n/2) + 1`; past `quorum_expiry` it cascades through the tier schedule and only authorizes establishment operations) before finalizing the update. Each cosigner independently validates the operation against their local state replica and verifies chain continuity from their validated tip before signing.

### Operator

    all_cosig_data = for each cosig entry (sorted by pubkey):
        cosign_signature (64 bytes)

    operator_signing_data = cosign_data || all_cosig_data
    sig_input = SHA256(operator_signing_data)

The operator signs after collecting the required majority of co-signatures. This seals the multilateral agreement — the operator's signature covers the content and all co-signatures.

## Operations

The `message` field contains a TLV-encoded operation. Type 0 is always a 1-byte discriminant. Deposit operations authorize via the dep-16 descriptor language — `pk()` is the common case, but the calculus generalizes miniscript with state predicates, proof obligations, and operation-type routing. See DEP-16 for the full grammar and admission rules; DEP-17 for the canonical encodings the fraud-proof system replays against.

### Discriminants

| Disc | Operation | Category |
|---|---|---|
| 1 | LedgerOpen | Lifecycle |
| 60 | LedgerClose | Lifecycle |
| 12 | QuorumBegin | Quorum |
| 43 | QuorumAddMember | Quorum |
| 44 | QuorumRemoveMember | Quorum |
| 46 | QuorumJoin | Quorum |
| 20 | DepositOpen | Deposits |
| 21 | DepositClose | Deposits |
| 23 | DepositKeyRotate | Deposits |
| 22 | FeeChange | Fees |
| 50 | FeeCollect | Fees |
| 30 | InvoiceCredit | Lightning |
| 31 | InvoiceLock | Lightning |
| 32 | InvoiceFail | Lightning |
| 33 | InvoiceFulfill | Lightning |
| 35 | OnchainCredit | On-chain |
| 36 | OnchainLock | On-chain |
| 37 | OnchainFail | On-chain |
| 38 | OnchainFulfill | On-chain |
| 70 | TransferLock | Transfers |
| 71 | TransferComplete | Transfers |
| 72 | TransferFail | Transfers |
| 54 | DisputeEnter | Dispute |
| 55 | DisputeAcquire | Dispute |
| 56 | DisputeYield | Dispute |
| 57 | DisputeArmed | Dispute |
| 80 | DeliveryEmbed | Delivery |

### Operation TLV Fields

#### Common

| Type | Name | Size |
|---|---|---|
| 0 | discriminant | 1 |
| 2 | amount | 8 |
| 36 | block_height | 4 |

#### Ledger

| Type | Name | Size | Used by |
|---|---|---|---|
| 56 | operator_id | 33 | LedgerOpen |
| 58 | reserves_id | variable | LedgerOpen, QuorumBegin, QuorumJoin |
| 62 | reserves_amount_msats | 8 | LedgerOpen, QuorumBegin (deposit capacity) |
| 82 | membership_expires | 4 | QuorumJoin |
| 84 | new_outpoint_txid | 32 | QuorumBegin |
| 86 | quorum_expiry | 4 | QuorumBegin (shortest member membership_until) |
| 42 | ledger_hash | 32 | QuorumBegin (tip hash committed at rotation) |
| 88 | collateral_amount_msats | 8 | LedgerOpen, QuorumBegin (security bond) |
| 90 | spending_txid | 32 | QuorumBegin |
| 92 | new_outpoint_vout | 4 | QuorumBegin |
| 96 | genesis_block | 4 | LedgerOpen |
| 6 | quorum_members | N*33 | QuorumBegin (concatenated 33-byte compressed pubkeys) |
| 276 | quorum_member_ledger_ids | variable | QuorumBegin (parallel to type 6, each entry `u8 len ‖ ledger_id_bytes`) |

#### Deposits

| Type | Name | Size | Used by |
|---|---|---|---|
| 16 | invoice | variable | DepositOpen (BOLT11 string, optional) |
| 18 | cosigner_sig | 64 | DepositOpen (co-signer guarantee, optional) |
| 24 | deposit_pubkey | 33 | DepositOpen |
| 200 | deposit_id | 16 | DepositOpen, DepositClose, FeeChange, DepositKeyRotate, FeeCollect |
| 202 | descriptor | variable | DepositOpen (miniscript) |
| 204 | witness | variable | TransferLock, DepositKeyRotate (nested) |
| 208 | new_descriptor | variable | DepositKeyRotate |
| 232 | receive_requires_sig | 1 | DepositOpen |

#### Fees

| Type | Name | Size | Used by |
|---|---|---|---|
| 12 | fees | variable | DepositOpen (nested FeeStructure) |
| 20 | new_fees | variable | FeeChange (nested FeeStructure) |
| 226 | transfer_fees | variable | DepositOpen (nested TransferFeeSchedule) |
| 244 | fee_change_after_blocks | 4 | DepositOpen |
| 246 | fee_change_notice_blocks | 4 | DepositOpen |
| 248 | fee_change_limit_bps | 2 | DepositOpen |
| 250 | effective_block | 4 | FeeChange |

#### Transfers

| Type | Name | Size | Used by |
|---|---|---|---|
| 210 | nonce | 32 | TransferLock |
| 212 | source_deposit_id | 16 | TransferLock |
| 214 | destination_deposit_id | 16 | TransferLock |
| 216 | completion_script | variable | TransferLock (miniscript) |
| 218 | timeout_height | 4 | TransferLock |
| 220 | transfer_id | 32 | TransferLock, TransferComplete, TransferFail |
| 222 | block_hash | 32 | TransferLock |
| 224 | script_witness | variable | TransferComplete (nested) |
| 228 | fail_reason | 1 | TransferFail (1=timeout, 0=reserved) |

#### Lightning

| Type | Name | Size | Used by |
|---|---|---|---|
| 14 | payment_hash | 32 | InvoiceCredit, InvoiceLock, InvoiceFulfill |
| 26 | invoice_id | variable | InvoiceCredit |
| 28 | sequence_number | 8 | InvoiceCredit, InvoiceLock, InvoiceFulfill |
| 30 | payment_id | 32 | InvoiceCredit, InvoiceLock, InvoiceFulfill |
| 34 | preimage | 32 | InvoiceFulfill |

#### On-chain

| Type | Name | Size | Used by |
|---|---|---|---|
| 66 | txid | 32 | OnchainCredit, OnchainFulfill |
| 68 | vout | 4 | OnchainCredit |
| 70 | destination_address | variable | OnchainLock, OnchainFulfill |
| 72 | withdrawal_id | 32 | OnchainLock, OnchainFail, OnchainFulfill |
| 74 | funding_address | variable | OnchainCredit |

#### Quorum

| Type | Name | Size | Used by |
|---|---|---|---|
| 44 | quorum_member | 33 | QuorumAddMember, QuorumRemoveMember |
| 46 | quorum_member_sig | 64 | QuorumBegin |
| 48 | operator_sig | 64 | QuorumBegin |
| 114 | member_ledger_id | variable | QuorumAddMember, QuorumJoin |
| 234 | min_fee_bps | 2 | QuorumAddMember |
| 236 | min_fee_fixed | 8 | QuorumAddMember |
| 238 | max_fee_period | 4 | QuorumAddMember |
| 242 | membership_until | 4 | QuorumAddMember |
| 252 | dispute_response_blocks | 4 | QuorumAddMember |
| 254 | dispute_arm_blocks | 4 | QuorumAddMember |
| 256 | service_response_blocks | 4 | QuorumAddMember |
| 258 | max_transfer_timeout_blocks | 4 | QuorumAddMember |
| 262 | max_descriptor_bytes | 4 | QuorumAddMember |
| 264 | compensation_bps | 2 | QuorumAddMember |
| 266 | compensation_deposit_id | 16 | QuorumAddMember |
| 268 | compensation_frequency_blocks | 4 | QuorumAddMember |

#### Dispute

| Type | Name | Size | Used by |
|---|---|---|---|
| 100 | reason | variable | DisputeEnter |
| 102 | last_valid_sequence | 8 | DisputeEnter |
| 108 | new_custodian | 33 | DisputeAcquire |
| 110 | claim_txid | 32 | DisputeAcquire |
| 118 | armed_block | 4 | DisputeArmed |
| 120 | new_reserves_address | variable | DisputeAcquire |
| 112 | commitment_hash | 20 | DisputeArmed (HASH160) |
| 122 | target_reserves | variable | DisputeArmed |

Field IDs 106 (entropy_block_hash) and 116 (entropy_block_height) were used by an earlier entropy-block-based DisputeAcquire shape and are now retired. Selection moved to an on-chain Tapscript lottery (see DEP-03 §"Custody Lottery"); `claim_txid` records the on-chain spend that proves the script-determined winner.

#### Delivery

| Type | Name | Size | Used by |
|---|---|---|---|
| 270 | request_hash | 32 | DeliveryEmbed |
| 272 | target_ledger_id | 32 | DeliveryEmbed |
| 274 | target_operator | 33 | DeliveryEmbed |

### Nested TLV: FeeStructure

| Type | Name | Size |
|---|---|---|
| 0 | annualized_msats | 8 |
| 2 | annualized_bps | 2 |
| 4 | frequency_blocks | 4 |

### Nested TLV: TransferFeeSchedule

| Type | Name | Size |
|---|---|---|
| 0 | fixed_msats | 8 |
| 2 | rate_bps | 2 |

## Batch (disc 90)

A single signed update can carry up to `MAX_BATCH_OPS = 64` inner operations via the `Batch` op type. The batch is **transactional**: all inner ops apply or none do. If any inner op fails validation or state-application, the entire batch is rejected and the ledger is left unchanged.

Wire format: the `Batch` op's TLV body carries a single `BATCH_OPS` field (tag 298) whose payload is

    u16 BE: inner-op count
    repeated: u32 BE inner-op length-prefix, inner-op TLV bytes

Each inner op is encoded as a standalone TLV-LedgerOperation; the outer Batch's TLV simply concatenates them with framing.

**Admission gates** (enforced both at TLV decode and at `validate_operation`):

- **Non-empty.** A batch with zero inner ops is rejected.
- **Bounded.** A batch with more than `MAX_BATCH_OPS` inner ops is rejected. The cap bounds both per-update validation cost and fraud-proof scanner cost — even though Batch nesting is forbidden, a single deep batch could pathologically inflate scan time.
- **Flat.** A `Batch` inside a `Batch` is rejected. Nesting would require a recursive guard everywhere a fraud scanner walks the history; the flat-only rule keeps the recursion at most one level deep.

**Fraud-proof semantics.** Scanners that look for a credit on a payment_hash or `(txid, vout)` (DEP-06 §"Uncredited") recurse into Batch contents: a `Batch` containing an `InvoiceCredit` for the disputed payment counts the same as a bare `InvoiceCredit`. This preserves the fraud-proof invariant that the operator can't hide a credit inside a batch to defeat detection.

**Cosignature semantics.** Batched updates carry exactly one set of cosignatures over the outer signed update (which encodes the Batch op in `message`). Cosigners validate by replaying the batch transactionally; on success they sign the same single SignedLedgerUpdate. This is the whole point — N operations cost one cosignature round.

**When to batch.** Agent commerce workloads where one wallet performs many micro-operations (e.g. a settlement service running hundreds of transfers per minute) benefit most. Single-operation updates remain valid and are still the right choice for high-value or one-shot operations where atomic-across-N is irrelevant.

## Related DEPs

- [DEP-03](DEP-03.md): On-chain transactions
- [DEP-04](DEP-04.md): Peer messaging
- [DEP-05](DEP-05.md): Quorum and collateral
- [DEP-06](DEP-06.md): Fraud proofs and recovery
- [DEP-07](DEP-07.md): Fee schedules
- [DEP-08](DEP-08.md): Deposits
- [DEP-09](DEP-09.md): Transfers
- [DEP-10](DEP-10.md): Payment channels
- [DEP-16](DEP-16.md): Self-modifying ledger-aware descriptors (the calculus deposit operations authorize against)
- [DEP-17](DEP-17.md): Canonical encodings (operation preimage, descriptor commitment, witness encoding)

## References

- [BOLT #1](https://github.com/lightning/bolts/blob/master/01-messaging.md) -- TLV encoding
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) -- Schnorr signatures, tagged hashing
