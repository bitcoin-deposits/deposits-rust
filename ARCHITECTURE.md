# Bitcoin Deposits Protocol — System Architecture and Protocol Specification

**Protocol Version:** 1
**Document Version:** 2026-02-25

The Bitcoin Deposits Protocol is a cryptographically auditable custody system for Bitcoin.
Operators maintain hash-chained ledgers that track deposits, reserves, and transfers with
100% reserve backing enforced on-chain. A quorum-based dispute mechanism enables custody
portability without trusted third parties.

---

## Table of Contents

- [1. System Overview](#1-system-overview)
  - [1.1 Design Goals](#11-design-goals)
  - [1.2 Security Model](#12-security-model)
  - [1.3 Crate Architecture](#13-crate-architecture)
  - [1.4 Glossary](#14-glossary)
- [2. Identifiers and Primitives](#2-identifiers-and-primitives)
  - [2.1 Ledger ID](#21-ledger-id)
  - [2.2 Deposit ID](#22-deposit-id)
  - [2.3 Transfer ID](#23-transfer-id)
  - [2.4 Key Derivation](#24-key-derivation)
  - [2.5 Hash Functions](#25-hash-functions)
- [3. TLV Encoding](#3-tlv-encoding)
  - [3.1 Format](#31-format)
  - [3.2 BigEndian Varint](#32-bigendian-varint)
  - [3.3 Canonical Ordering](#33-canonical-ordering)
  - [3.4 Even/Odd Semantics](#34-evenodd-semantics)
  - [3.5 Nested TLV](#35-nested-tlv)
- [4. Hash Chain](#4-hash-chain)
  - [4.1 SignedLedgerUpdate](#41-signedledgerupdate)
  - [4.2 Hash Computation](#42-hash-computation)
  - [4.3 Chain Verification](#43-chain-verification)
- [5. Signing Model](#5-signing-model)
  - [5.1 Protocol-Level Co-Signing](#51-protocol-level-co-signing)
  - [5.2 BDK Operator-Only Mode](#52-bdk-operator-only-mode)
  - [5.3 Cosigner Binding](#53-cosigner-binding)
  - [5.4 Sign-and-Broadcast Flow](#54-sign-and-broadcast-flow)
- [6. Ledger State](#6-ledger-state)
  - [6.1 LedgerState Fields](#61-ledgerstate-fields)
  - [6.2 Deposit](#62-deposit)
  - [6.3 ReservesOutput](#63-reservesoutput)
  - [6.4 Balance Model](#64-balance-model)
  - [6.5 Quorum State](#65-quorum-state)
  - [6.6 Pending State](#66-pending-state)
  - [6.7 Dispute State](#67-dispute-state)
- [7. LedgerOperation Enum](#7-ledgeroperation-enum)
  - [7.1 Discriminant Map](#71-discriminant-map)
  - [7.2 Lifecycle Operations](#72-lifecycle-operations)
  - [7.3 Reserves Operations](#73-reserves-operations)
  - [7.4 Deposit Operations](#74-deposit-operations)
  - [7.5 Invoice Operations](#75-invoice-operations)
  - [7.6 On-Chain Operations](#76-on-chain-operations)
  - [7.7 Transfer Operations](#77-transfer-operations)
  - [7.8 Collateral Operations](#78-collateral-operations)
  - [7.9 Quorum Operations](#79-quorum-operations)
  - [7.10 Maintenance Operations](#710-maintenance-operations)
  - [7.11 Dispute Operations](#711-dispute-operations)
- [8. Wire Protocol](#8-wire-protocol)
  - [8.1 Envelope Types](#81-envelope-types)
  - [8.2 Operation Constants](#82-operation-constants)
- [9. Transfer Protocol](#9-transfer-protocol)
  - [9.1 Flow](#91-flow)
  - [9.2 State Mutations](#92-state-mutations)
  - [9.3 Fee Calculation](#93-fee-calculation)
- [10. Quorum and Collateral](#10-quorum-and-collateral)
  - [10.1 Two-Sided Trail](#101-two-sided-trail)
  - [10.2 Collateral Attestation](#102-collateral-attestation)
  - [10.3 Ratchet Semantics](#103-ratchet-semantics)
  - [10.4 Reserves Rotation](#104-reserves-rotation)
- [11. Dispute State Machine](#11-dispute-state-machine)
  - [11.1 State Diagram](#111-state-diagram)
  - [11.2 Transition Rules](#112-transition-rules)
  - [11.3 Signer Authorization](#113-signer-authorization)
  - [11.4 Entropy Selection](#114-entropy-selection)
  - [11.5 On-Chain Resolution](#115-on-chain-resolution)
- [12. Nostr Transport](#12-nostr-transport)
  - [12.1 Event Kinds](#121-event-kinds)
  - [12.2 Tag Schema](#122-tag-schema)
  - [12.3 Subscription and Polling](#123-subscription-and-polling)
  - [12.4 Request Actions](#124-request-actions)
- [13. Persistence](#13-persistence)
  - [13.1 JSONL Format](#131-jsonl-format)
  - [13.2 Append-Only Strategy](#132-append-only-strategy)
  - [13.3 Load and Replay](#133-load-and-replay)
- [14. Validation Rules](#14-validation-rules)
  - [14.1 Global Invariants](#141-global-invariants)
  - [14.2 Per-Operation Validation](#142-per-operation-validation)
  - [14.3 Conformance Checking](#143-conformance-checking)
- [15. Constants Reference](#15-constants-reference)
- [16. Source Cross-Reference](#16-source-cross-reference)

---

## 1. System Overview

### 1.1 Design Goals

- **100% reserves backing** — every deposited satoshi is backed by an on-chain UTXO
- **Cryptographic auditability** — hash-chained ledger history is independently verifiable
- **Operator accountability** — quorum members can dispute and replace misbehaving operators
- **Custody portability** — deposits can be transferred to a new operator via the dispute mechanism

### 1.2 Security Model

The protocol enforces a **100% + 100% backing model**, funded entirely by the operator:

1. **Reserves**: on-chain UTXOs controlled by the operator must cover 100% of deposit balances
2. **Collateral**: the operator funds deposits on quorum member ledgers and locks those funds as
   collateral, providing a second 100% layer

Together this provides 200% total backing using operator funds only — no quorum member capital
is at risk. The reserves are directly spendable by the operator (subject to timelock and
quorum co-spending paths after rotation). The collateral is locked on quorum members' ledgers
via `CollateralLock` operations and attested cryptographically back to the operator's ledger.

### 1.3 Crate Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    deposits-tools                       │
│            (testing, simulation, admin)                 │
├─────────────────────────────────────────────────────────┤
│                    deposits-node                        │
│              (BDK wallet + Nostr transport)             │
├─────────────────────────────────────────────────────────┤
│                    deposits-core                        │
│         (types, messages, TLV, validation)              │
└─────────────────────────────────────────────────────────┘
```

| Crate | Purpose | I/O |
|-------|---------|-----|
| `deposits-core` | Protocol library: types, messages, TLV codec, validation, ledger state machine | None — pure logic |
| `deposits-node` | BDK wallet node: daemon, CLI, Nostr transport, JSONL persistence | Disk, network, Bitcoin RPC |
| `deposits-tools` | Testing harnesses, payment simulator, admin utilities | Various |

### 1.4 Glossary

| Term | Definition |
|------|-----------|
| **Ledger** | Hash-chained sequence of signed updates tracking deposits, reserves, and transfers for one operator |
| **Operator** | Entity running a node that creates and manages a ledger |
| **Partner** | Co-signer that validates and countersigns operator updates (LDK channel partner) |
| **Quorum Member** | Operator who joins another operator's quorum to monitor their ledger and participate in dispute resolution. The monitored operator funds deposits on the quorum member's ledger as collateral |
| **Reserves** | On-chain UTXO(s) backing deposit balances, controlled by the operator |
| **Collateral** | Operator funds deposited on quorum member ledgers and locked via `CollateralLock`, providing a second layer of backing |
| **Deposit** | A customer-facing account within a ledger, identified by a descriptor |
| **Descriptor** | Miniscript spending policy controlling a deposit |
| **Attestation** | Cryptographic proof that operator-funded collateral is locked on a quorum member's ledger |
| **Dispute** | Process by which a quorum member challenges an operator and potentially acquires custody |

---

## 2. Identifiers and Primitives

### 2.1 Ledger ID

32-byte identifier uniquely binding an operator to their reserves and genesis block.

```
LedgerID = SHA256(operator_pubkey[33] || reserves_key_bytes[var] || genesis_block[4,LE])
```

- `operator_pubkey`: 33-byte compressed secp256k1 public key
- `reserves_key_bytes`: UTF-8 bytes of the reserves identifier string (UTXO address for BDK, partner pubkey for LDK)
- `genesis_block`: 4-byte little-endian block height at ledger creation

> Source: `types.rs:1131-1142` — `compute_ledger_id()`

### 2.2 Deposit ID

16-byte identifier derived from the deposit's descriptor.

```
DepositID = SHA256(descriptor_string)[0..16]
```

Truncation to 16 bytes provides 128-bit collision resistance, sufficient for per-ledger uniqueness.

> Source: `types.rs:217-222` — `compute_deposit_id()`

### 2.3 Transfer ID

32-byte identifier computed as the hash of the transfer signing message.

```
TransferID = SHA256(transfer_signing_message)
```

Stored in `PendingTransfer.transfer_id: [u8; 32]`.

### 2.4 Key Derivation

| Path | Usage | Scheme |
|------|-------|--------|
| `m/86'/0'/0'/0/0` | Operator identity key | BIP-86 Taproot |
| `m/84'/0'/0'/0/*` | BDK wallet addresses | BIP-84 native SegWit |

These are distinct derivation paths — the operator key cannot sign for wallet addresses and vice versa.

### 2.5 Hash Functions

| Function | Usage |
|----------|-------|
| SHA-256 | Ledger ID, deposit ID, transfer ID, hash chain, signing data, entropy selection |
| HASH160 (SHA-256 then RIPEMD-160) | Lottery commitment in CustodyArmed (20-byte `commitment_hash`) |
| ECDSA over SHA-256 | Partner and operator co-signatures |
| Schnorr over SHA-256 | BDK operator-only signatures |

---

## 3. TLV Encoding

All protocol messages and ledger operations use a Type-Length-Value encoding.

### 3.1 Format

```
record := varint(type) || varint(length) || value[length]
stream := record*  (zero or more records, sorted by type)
```

Each TLV stream is an ordered sequence of records. The container is a `BTreeMap<u64, Vec<u8>>`
which automatically enforces ascending type order.

> Source: `tlv.rs:149-255` — `TlvStream`

### 3.2 BigEndian Varint

| Byte Range | Encoding | Size |
|------------|----------|------|
| `0x00–0xFC` | Direct value | 1 byte |
| `0xFD–0xFFFF` | `0xFD` ‖ value[2,BE] | 3 bytes |
| `0x10000–0xFFFFFFFF` | `0xFE` ‖ value[4,BE] | 5 bytes |
| `0x100000000–0xFFFFFFFFFFFFFFFF` | `0xFF` ‖ value[8,BE] | 9 bytes |

Decoding enforces minimal encoding: a 3-byte varint must have value >= 0xFD, a 5-byte must
have value > 0xFFFF, and a 9-byte must have value > 0xFFFFFFFF.

> Source: `tlv.rs:91-141` — `write_varint()`, `read_varint()`

### 3.3 Canonical Ordering

Types must appear in strictly ascending order. Duplicate types are rejected. Violation
produces `TlvError::NonCanonicalOrder`.

> Source: `tlv.rs:217-223`

### 3.4 Even/Odd Semantics

- **Even types** (0, 2, 4, ...): Required fields. Missing even fields produce `MissingRequiredField` error.
- **Odd types** (1, 3, 5, ...): Optional fields. Unknown odd types are silently skipped.

### 3.5 Nested TLV

Complex types are encoded as nested TLV streams within a parent field's value:

- **FeeStructure**: `annualized_fixed` (u64) + `annualized_bps` (u16) + `frequency_blocks` (u32)
- **TransferFeeSchedule**: `fixed_sats` (u64) + `rate_bps` (u16)
- **DescriptorWitness**: `varint(count) || (varint(elem_len) || elem_bytes)*`
  - Max stack size: 1000 elements
  - Max element size: 520 bytes
- **Vectors**: `varint(count) || (varint(item_len) || item_tlv_bytes)*`
  - Max count: 1,000,000
  - Max item length: 16 MB

> Source: `tlv.rs:492-528` — `TlvBuilder::nested()`, `witness_field()`, `vec_field()`

---

## 4. Hash Chain

### 4.1 SignedLedgerUpdate

Each update in the ledger history is a `SignedLedgerUpdate`:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `message` | `Vec<u8>` | variable | TLV-encoded ledger operation |
| `message_type` | `u16` | 2 | Operation wire type for quick filtering |
| `operator_id` | `PublicKey` | 33 | Operator's compressed public key |
| `ledger_id` | `[u8; 32]` | 32 | Ledger identifier |
| `sequence_number` | `u64` | 8 | Monotonically increasing counter (starts at 0) |
| `previous_hash` | `[u8; 32]` | 32 | Hash of previous update (all zeros for genesis) |
| `current_hash` | `[u8; 32]` | 32 | Hash of this update |
| `timestamp` | `u64` | 8 | Unix timestamp of creation |
| `block_height` | `u32` | 4 | Block height at creation |
| `block_hash` | `[u8; 32]` | 32 | Block hash at creation |
| `partner_signature` | `[u8; 64]` | 64 | Partner's ECDSA signature (zeros if unsigned) |
| `operator_signature` | `[u8; 64]` | 64 | Operator's signature |

> Source: `types.rs:1414-1446`

### 4.2 Hash Computation

```
current_hash = SHA256(sequence_number[8,LE] || previous_hash[32] || message[var])
```

The hash binds the sequence, the chain history (via `previous_hash`), and the operation content.

> Source: `types.rs:1457-1469` — `compute_hash()`

### 4.3 Chain Verification

To verify a ledger's hash chain:

1. **Genesis check**: `updates[0].sequence_number == 0` and `updates[0].previous_hash == [0; 32]`
2. **Sequence continuity**: for each update `i > 0`, `updates[i].sequence_number == updates[i-1].sequence_number + 1`
3. **Hash linkage**: for each update `i > 0`, `updates[i].previous_hash == updates[i-1].current_hash`
4. **Hash integrity**: for each update, `update.current_hash == SHA256(seq || prev_hash || message)`
5. **Signature validity**: verify operator (and optionally partner) signatures per update

---

## 5. Signing Model

### 5.1 Protocol-Level Co-Signing

The two-phase co-signing protocol ensures both partner and operator commit to the same update.
Both use **ECDSA** over secp256k1.

**Partner signing data:**

```
partner_signing_data = message || message_type[2,LE] || sequence_number[8,LE]
                     || previous_hash[32] || current_hash[32] || timestamp[8,LE]
```

The partner signs `SHA256(partner_signing_data)` with ECDSA, producing a 64-byte compact signature.

> Source: `types.rs:1485-1535`

**Operator signing data:**

```
operator_signing_data = partner_signing_data || partner_signature[64]
```

The operator signs `SHA256(operator_signing_data)` with ECDSA. By including the partner's
signature in the operator's signing input, the operator commits to the partner's attestation.

> Source: `types.rs:1501-1552`

### 5.2 BDK Operator-Only Mode

When no LDK channel partner exists (BDK-only deployment), the operator uses **Schnorr** signing:

```
sig_input = sequence_number[8,LE] || previous_hash[32] || current_hash[32] || message[var]
signature = Schnorr(SHA256(sig_input), operator_keypair)
```

The `partner_signature` field remains all zeros in this mode.

> Source: `node.rs:311-321` — `sign_last_update()`

### 5.3 Cosigner Binding

After a `ReservesRotate` operation, all subsequent updates **require** a co-signature from a
quorum member. The `member_ledger_hash` field in the co-signed update ties the co-signer's
own ledger state to the attestation, preventing the co-signer from signing with stale state.

**Exception**: `CustodyDispute` operations can omit the co-signature, since they are initiated
by a quorum member challenging the operator.

> Source: `ledger.rs:422-442`

### 5.4 Sign-and-Broadcast Flow

The `sign_and_broadcast()` function orchestrates the full signing flow:

1. Check if reserves have been rotated (quorum co-signatures required)
2. If quorum members exist:
   a. Request co-signature via Nostr (`cosign_update` action)
   b. Retry up to 3 times with 500ms between attempts
   c. Apply partner signature on success
   d. Fall back to operator-only if before rotation
3. Sign as operator (Schnorr)
4. Validate hash chain integrity
5. Persist to disk
6. Broadcast via Nostr (Kind 9100)

> Source: `node.rs:6665-6775` — `sign_and_broadcast()`

---

## 6. Ledger State

### 6.1 LedgerState Fields

| Field | Type | Description |
|-------|------|-------------|
| `ledger_id` | `[u8; 32]` | Unique identifier |
| `genesis_block` | `u32` | Block height at creation |
| `operator_key` | `PublicKey` | Current operator's public key |
| `reserves_key` | `String` | Reserves identifier |
| `ledger_address` | `String` | Ledger address |
| `deposits` | `HashMap<DepositId, Deposit>` | All deposits |
| `reserves` | `ReservesOutput` | Current reserves UTXO |
| `pending_invoice` | `Option<PendingInvoice>` | Pending Lightning invoice |
| `quorum_members` | `Vec<QuorumMember>` | Quorum backing providers |
| `collateral_amount` | `u64` | Collateral committed on this ledger by outside operators (sats) |
| `last_collateral_increase_block` | `Option<u32>` | Block of last collateral increase |
| `collateral_enforcement_block` | `Option<u64>` | Block when collateral requirements enforced |
| `received_collateral_amount` | `u64` | Collateral received from others (sats) |
| `collateral_attestations` | `HashMap<PublicKey, CollateralAttestation>` | Per-member attestations |
| `partner_deepest_ack_hash` | `[u8; 32]` | Partner's deepest ACK |
| `channel_deepest_commitment_hash` | `[u8; 32]` | Channel commitment hash |
| `last_updated` | `u64` | Last update Unix timestamp |
| `pending_updates` | `HashMap<u64, SignedLedgerUpdate>` | Out-of-order update queue |
| `pending_transfers` | `HashMap<[u8; 32], PendingTransfer>` | Active conditional transfers |
| `sequence` | `u64` | Current sequence number |
| `hash` | `[u8; 32]` | Current ledger hash |
| `joined_quorums` | `Vec<QuorumMembership>` | Quorums we have joined |
| `dispute_state` | `DisputeState` | Current dispute state |
| `parent_pubkey` | `PublicKey` | Authorized signer for updates |
| `quorum_at_fork` | `Vec<QuorumMember>` | Quorum snapshot at dispute |
| `dispute_fork_sequence` | `u64` | Sequence before dispute |

> Source: `types.rs:1013-1128`

The `Ledger` struct wraps `LedgerState` with role and history:

```rust
pub struct Ledger {
    pub state: LedgerState,
    pub role: LedgerRole,               // Operator, Partner, or Auditor
    pub history: Vec<SignedLedgerUpdate>,
}
```

> Source: `ledger.rs:105-112`

### 6.2 Deposit

| Field | Type | Description |
|-------|------|-------------|
| `deposit_id` | `DepositId` ([u8; 16]) | Unique identifier |
| `descriptor` | `String` | Miniscript descriptor |
| `balance` | `u64` | Current balance (millisatoshis) |
| `locked_balance` | `u64` | Locked for pending transfers (millisatoshis) |
| `invoices` | `Vec<Invoice>` | Outstanding unexpired invoices |
| `fees` | `FeeStructure` | Periodic custody fee schedule |
| `last_fee_assessment` | `u32` | Block height of last fee collection |
| `collateral_lock_amount` | `u64` | Operator funds locked as collateral on this deposit (millisatoshis) |
| `collateral_lock_expires` | `u32` | Block when collateral lock expires |
| `transfer_fees` | `TransferFeeSchedule` | Per-transfer fee schedule |

> Source: `types.rs:591-623`

### 6.3 ReservesOutput

| Field | Type | Description |
|-------|------|-------------|
| `channel_id` | `[u8; 32]` | Associated channel ID |
| `amount` | `u64` | Amount held in reserves (satoshis) |
| `spend_to` | `PublicKey` | Key that can spend reserves after timelock |

> Source: `types.rs:732-751`

### 6.4 Balance Model

```
available_balance = balance - locked_balance
```

All deposit balances are in **millisatoshis**. Reserves are in **satoshis**. The reserve
invariant converts:

```
required_reserves_sats = total_deposit_balance_msats / 1000
reserves.amount >= required_reserves_sats
```

> Source: `ledger.rs:227-230` — `required_reserves()`

### 6.5 Quorum State

**QuorumMember** — a member providing backing to our ledger:

| Field | Type | Description |
|-------|------|-------------|
| `pubkey` | `PublicKey` | Member's public key |
| `ledger_id` | `String` | Member's ledger where collateral is locked |

> Source: `types.rs:805-811`

**QuorumMembership** — a quorum we have joined (on another operator's ledger):

| Field | Type | Description |
|-------|------|-------------|
| `operator_id` | `PublicKey` | Operator whose quorum we joined |
| `ledger_id` | `String` | Ledger ID we're monitoring |
| `membership_expires` | `u32` | Expiry block height |
| `our_signature` | `[u8; 64]` | Our consent signature |
| `joined_at_sequence` | `u64` | Sequence when we joined |

> Source: `types.rs:783-797`

### 6.6 Pending State

**PendingTransfer** — conditional transfer in flight:

| Field | Type | Description |
|-------|------|-------------|
| `transfer_id` | `[u8; 32]` | Unique transfer identifier |
| `nonce` | `[u8; 32]` | Collision prevention nonce |
| `source_deposit_id` | `DepositId` | Source deposit |
| `destination_deposit_id` | `DepositId` | Destination deposit |
| `amount` | `u64` | Transfer amount (excluding fee) |
| `fee` | `u64` | Custodian fee |
| `completion_script` | `String` | Miniscript descriptor (e.g., `sha256(H)`) |
| `timeout_height` | `u32` | Refund block height |

`total_locked() = amount + fee`

> Source: `types.rs:554-576`

**PendingInvoice** — Lightning invoice awaiting payment:

| Field | Type | Description |
|-------|------|-------------|
| `amount` | `u64` | Invoice amount (millisatoshis) |
| `payment_hash` | `[u8; 32]` | Payment hash |
| `expires` | `u64` | Expiration Unix timestamp |
| `assigned_deposit` | `DepositId` | Receiving deposit |
| `invoice_id` | `String` | Invoice identifier |
| `bolt11` | `String` | BOLT11 invoice string |

> Source: `types.rs:521-543`

### 6.7 Dispute State

```rust
pub enum DisputeState {
    Normal,      // Default — all normal operations allowed
    Disputed,    // Dispute opened — only quorum rebuild + arm allowed
    Armed,       // Candidate locked in — only acquire/yield allowed
    Tombstoned,  // Branch terminated — no operations allowed
}
```

> Source: `types.rs:909-922`

---

## 7. LedgerOperation Enum

### 7.1 Discriminant Map

| Disc | Operation | Category |
|-----:|-----------|----------|
| 1 | `LedgerOpen` | Lifecycle |
| 10 | `ReservesIncrease` | Reserves |
| 11 | `ReservesDecrease` | Reserves |
| 12 | `ReservesRotate` | Reserves |
| 20 | `DepositOpen` | Deposits |
| 21 | `DepositClose` | Deposits |
| 22 | `DepositUpdate` | Deposits |
| 23 | `DepositKeyRotate` | Deposits |
| 30 | `InvoiceCredit` | Invoices |
| 31 | `InvoiceLock` | Invoices |
| 32 | `InvoiceFail` | Invoices |
| 33 | `InvoiceFulfill` | Invoices |
| 35 | `OnchainCredit` | On-chain |
| 36 | `OnchainLock` | On-chain |
| 37 | `OnchainFail` | On-chain |
| 38 | `OnchainFulfill` | On-chain |
| 40 | `CollateralIncrease` | Collateral |
| 41 | `CollateralDecrease` | Collateral |
| 42 | `CollateralAttestation` | Collateral |
| 43 | `QuorumAddMember` | Quorum |
| 44 | `QuorumRemoveMember` | Quorum |
| 45 | `CollateralLock` | Quorum |
| 46 | `QuorumJoin` | Quorum |
| 50 | `FeeCollect` | Maintenance |
| 54 | `CustodyDispute` | Dispute |
| 55 | `CustodyAcquire` | Dispute |
| 56 | `CustodyYield` | Dispute |
| 57 | `CustodyArmed` | Dispute |
| 60 | `LedgerClose` | Lifecycle |
| 61 | `Tombstone` | Lifecycle |

> Source: `messages.rs:866-903` — `discriminant()`

### 7.2 Lifecycle Operations

**LedgerOpen** (disc=1) — Initialize a new ledger.

| Field | Type | TLV ID |
|-------|------|--------|
| `operator_id` | `PublicKey` | 56 |
| `reserves_id` | `String` | 58 |
| `ledger_address` | `String` | 60 |
| `genesis_block` | `u32` | 96 |
| `collateral_enforcement_block` | `u64` | 64 |

State changes: sets `operator_key`, `reserves_key`, `ledger_address`, `genesis_block`, `ledger_id`, `collateral_enforcement_block`.

**LedgerClose** (disc=60) — Close a ledger. No fields.

**Tombstone** (disc=61) — Permanently deactivate a ledger.

| Field | Type | TLV ID |
|-------|------|--------|
| `channel_id` | `[u8; 32]` | 50 |
| `close_reason` | `Option<String>` | 52 |
| `timestamp` | `u64` | 54 |

State changes: clears `collateral_attestations`.

### 7.3 Reserves Operations

**ReservesIncrease** (disc=10) — Increase reserves backing.

| Field | Type | TLV ID |
|-------|------|--------|
| `reserves_id` | `String` | 58 |
| `new_amount` | `u64` | 8 |

Validation: `new_amount > current_amount` (or `current_amount == 0` for initial).

**ReservesDecrease** (disc=11) — Decrease reserves.

| Field | Type | TLV ID |
|-------|------|--------|
| `reserves_id` | `String` | 58 |
| `new_amount` | `u64` | 8 |

Validation: `new_amount < current_amount` AND `new_amount >= required_reserves()`.

**ReservesRotate** (disc=12) — Rotate to new reserves UTXO with quorum-controlled spend paths.

| Field | Type | TLV ID |
|-------|------|--------|
| `reserves_id` | `String` | 58 |
| `spending_txid` | `[u8; 32]` | 90 |
| `new_outpoint_txid` | `[u8; 32]` | 91 |
| `new_outpoint_vout` | `u32` | 92 |
| `amount` | `u64` | 2 |
| `quorum_threshold` | `u8` | 93 |
| `quorum_size` | `u8` | 94 |
| `first_expiry_block` | `u32` | 95 |
| `ledger_hash` | `[u8; 32]` | 42 |

After rotation, all subsequent updates require co-signature from a quorum member.

### 7.4 Deposit Operations

**DepositOpen** (disc=20) — Create a new deposit.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `descriptor` | `String` | 202 |
| `fees` | `Option<FeeStructure>` | 12 |
| `transfer_fees` | `Option<TransferFeeSchedule>` | 226 |
| `payment_hash` | `Option<[u8; 32]>` | 14 |
| `invoice` | `Option<String>` | 16 |
| `cosigner_guarantee_signature` | `Option<[u8; 64]>` | 18 |

State changes: creates new `Deposit` in `deposits` map with zero balance.

**DepositClose** (disc=21) — Remove a deposit.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |

Validation: `deposit.balance == 0`, no outstanding invoices.

**DepositUpdate** (disc=22) — Update deposit fee structure.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `new_fees` | `FeeStructure` | 20 |

**DepositKeyRotate** (disc=23) — Rotate deposit descriptor.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `new_descriptor` | `String` | 208 |
| `witness` | `DescriptorWitness` | 204 |

### 7.5 Invoice Operations

**InvoiceCredit** (disc=30) — Credit a deposit from a Lightning invoice.

| Field | Type | TLV ID |
|-------|------|--------|
| `payment_hash` | `[u8; 32]` | 14 |
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `invoice_id` | `String` | 26 |
| `sequence_number` | `u64` | 28 |

State: `deposit.balance += amount`.

**InvoiceLock** (disc=31) — Lock funds for outgoing Lightning payment.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `payment_id` | `[u8; 32]` | 30 |
| `sequence_number` | `u64` | 28 |
| `witness` | `DescriptorWitness` | 204 |

Validation: `deposit.available_balance() >= amount`.

**InvoiceFail** (disc=32) — Release locked invoice funds.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `payment_id` | `[u8; 32]` | 30 |
| `sequence_number` | `u64` | 28 |

**InvoiceFulfill** (disc=33) — Settle outgoing Lightning payment.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `payment_id` | `[u8; 32]` | 30 |
| `sequence_number` | `u64` | 28 |
| `witness` | `DescriptorWitness` | 204 |
| `preimage` | `[u8; 32]` | 34 |

### 7.6 On-Chain Operations

**OnchainCredit** (disc=35) — Credit deposit from confirmed on-chain transaction.

| Field | Type | TLV ID |
|-------|------|--------|
| `txid` | `[u8; 32]` | 66 |
| `vout` | `u32` | 68 |
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `funding_address` | `String` | 74 |

State: `deposit.balance += amount`.

**OnchainLock** (disc=36) — Lock funds for on-chain withdrawal.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `fee_sats` | `u64` | 12 |
| `destination_address` | `String` | 70 |
| `withdrawal_id` | `[u8; 32]` | 72 |
| `witness` | `DescriptorWitness` | 204 |

**OnchainFail** (disc=37) — Release locked withdrawal funds.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `withdrawal_id` | `[u8; 32]` | 72 |

**OnchainFulfill** (disc=38) — Confirm on-chain withdrawal.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `withdrawal_id` | `[u8; 32]` | 72 |
| `amount` | `u64` | 2 |
| `txid` | `[u8; 32]` | 66 |
| `destination_address` | `String` | 70 |

### 7.7 Transfer Operations

**TransferLock** (disc=70) — Lock funds for conditional transfer.

| Field | Type | TLV ID |
|-------|------|--------|
| `nonce` | `[u8; 32]` | 210 |
| `source_deposit_id` | `DepositId` | 212 |
| `destination_deposit_id` | `DepositId` | 214 |
| `amount` | `u64` | 2 |
| `fee` | `u64` | 12 |
| `completion_script` | `String` | 216 |
| `timeout_height` | `u32` | 218 |
| `transfer_id` | `[u8; 32]` | 220 |
| `witness` | `DescriptorWitness` | 204 |

State: `source.balance -= (amount + fee)`, `source.locked_balance += (amount + fee)`, creates `PendingTransfer`.

**TransferComplete** (disc=71) — Complete transfer with witness satisfaction.

| Field | Type | TLV ID |
|-------|------|--------|
| `transfer_id` | `[u8; 32]` | 220 |
| `script_witness` | `DescriptorWitness` | 224 |

State: removes `PendingTransfer`, credits `destination.balance += amount`, deducts from `source.locked_balance`, fee consumed.

**TransferTimeout** (disc=72) — Refund timed-out transfer.

| Field | Type | TLV ID |
|-------|------|--------|
| `transfer_id` | `[u8; 32]` | 220 |
| `block_hash` | `[u8; 32]` | 222 |

State: returns locked funds to source (`source.balance += amount + fee`, `source.locked_balance -= amount + fee`), removes `PendingTransfer`.

### 7.8 Collateral Operations

**CollateralIncrease** (disc=40) — Increase the operator's committed collateral amount.

| Field | Type | TLV ID |
|-------|------|--------|
| `new_amount` | `u64` | 8 |
| `block_height` | `u32` | 36 |

**CollateralDecrease** (disc=41) — Decrease the operator's committed collateral amount.

| Field | Type | TLV ID |
|-------|------|--------|
| `new_amount` | `u64` | 8 |
| `block_height` | `u32` | 36 |

**CollateralAttestation** (disc=42) — Record proof that operator-funded collateral is locked on a quorum member's ledger.

| Field | Type | TLV ID |
|-------|------|--------|
| `collateral_operator` | `PublicKey` | 38 |
| `quorum_member` | `PublicKey` | 44 |
| `collateral_ledger_id` | `String` | 115 |
| `amount` | `u64` | 2 |
| `block_height` | `u32` | 36 |
| `lock_until_block` | `u32` | 76 |
| `signature` | `[u8; 64]` | 40 |
| `ledger_hash` | `[u8; 32]` | 42 |

State: inserts into `collateral_attestations`, recalculates `received_collateral_amount`.

### 7.9 Quorum Operations

**QuorumAddMember** (disc=43) — Add a quorum member to operator's ledger.

| Field | Type | TLV ID |
|-------|------|--------|
| `quorum_member` | `PublicKey` | 44 |
| `quorum_member_signature` | `[u8; 64]` | 46 |
| `member_ledger_id` | `String` | 114 |

State: appends to `quorum_members`.

**QuorumRemoveMember** (disc=44) — Remove a quorum member.

| Field | Type | TLV ID |
|-------|------|--------|
| `quorum_member` | `PublicKey` | 44 |
| `operator_signature` | `[u8; 64]` | 48 |

State: removes from `quorum_members`, removes their attestations.

**CollateralLock** (disc=45) — Lock operator-funded deposit balance as collateral on a quorum member's ledger.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `lock_until_block` | `u32` | 76 |
| `operator_id` | `PublicKey` | 56 |
| `witness` | `DescriptorWitness` | 204 |

State: sets `deposit.collateral_lock_amount` and `deposit.collateral_lock_expires` (ratchet: can only increase amount / extend duration).

**QuorumJoin** (disc=46) — Record on our own ledger that we joined another operator's quorum.

| Field | Type | TLV ID |
|-------|------|--------|
| `operator_id` | `PublicKey` | 56 |
| `ledger_id` | `String` | 58 (wire name: RESERVES_ID) |
| `membership_expires` | `u32` | 82 |
| `our_signature` | `[u8; 64]` | 80 |

State: updates `joined_quorums` (renewal or new entry).

> Note: The TLV field ID is `RESERVES_ID` (58) for wire compatibility, but the Rust field is named `ledger_id`.

### 7.10 Maintenance Operations

**FeeCollect** (disc=50) — Collect custody fees from a deposit.

| Field | Type | TLV ID |
|-------|------|--------|
| `deposit_id` | `DepositId` | 200 |
| `amount` | `u64` | 2 |
| `block_height` | `u32` | 36 |

State: `deposit.balance -= amount`, updates `deposit.last_fee_assessment`.

### 7.11 Dispute Operations

**CustodyDispute** (disc=54) — Open a dispute against the operator.

| Field | Type | TLV ID |
|-------|------|--------|
| `last_valid_sequence` | `u64` | 102 |
| `reason` | `String` | 100 |

State: snapshots `quorum_at_fork`, clears `collateral_attestations`, records `dispute_fork_sequence`, sets `dispute_state = Disputed`. The quorum is **not disbanded** — existing members continue co-signing updates throughout the dispute process and persist through `CustodyAcquire` for the new custodian. Attestations are voided so the new custodian must collect fresh proofs before `CustodyArmed`.

**This is the only operation that may be signed by a quorum member** (not the operator).

**CustodyArmed** (disc=57) — Lock in candidate for entropy selection.

| Field | Type | TLV ID |
|-------|------|--------|
| `armed_block` | `u32` | 109 |
| `commitment_hash` | `[u8; 20]` | 112 |
| `target_reserves` | `String` | 113 |

`commitment_hash` is a 20-byte HASH160 of the lottery preimage.

State: sets `dispute_state = Armed`.

**CustodyAcquire** (disc=55) — Transfer custody to the winning candidate.

| Field | Type | TLV ID |
|-------|------|--------|
| `new_custodian` | `PublicKey` | 108 |
| `entropy_block_height` | `u32` | 105 |
| `entropy_block_hash` | `[u8; 32]` | 106 |
| `spend_txid` | `[u8; 32]` | 110 |
| `new_reserves_address` | `String` | 111 |

State: `operator_key = new_custodian`, `parent_pubkey = new_custodian`, clears dispute state to `Normal`, clears `quorum_at_fork` and `dispute_fork_sequence`.

**CustodyYield** (disc=56) — Yield custody (loser of entropy selection). No fields.

State: sets `dispute_state = Tombstoned`.

---

## 8. Wire Protocol

### 8.1 Envelope Types

All envelope types use odd values for BOLT 1 compatibility.

| Type | Hex | Name |
|-----:|----:|------|
| 32769 | `0x8001` | `LEDGER_UPDATE` |
| 32771 | `0x8003` | `LEDGER_UPDATE_RESPONSE` |
| 32773 | `0x8005` | `HANDSHAKE` |
| 32775 | `0x8007` | `HANDSHAKE_RESPONSE` |
| 32777 | `0x8009` | `SYNC` |
| 32779 | `0x800B` | `SYNC_RESPONSE` |
| 32781 | `0x800D` | `RECOVERY` |
| 32783 | `0x800F` | `RECOVERY_RESPONSE` |
| 32785 | `0x8011` | `COORDINATION` |
| 32787 | `0x8013` | `COORDINATION_RESPONSE` |
| 32789 | `0x8015` | `RELAY` |
| 32791 | `0x8017` | `RELAY_RESPONSE` |

> Source: `messages.rs:44-152`

### 8.2 Operation Constants

Selected wire constants for operation types (0x80xx range):

| Hex | Name | Category |
|----:|------|----------|
| `0x80B1` | `RESERVES_INCREASE` | Reserves |
| `0x80B3` | `RESERVES_DECREASE` | Reserves |
| `0x80B5` | `RESERVES_ROTATE` | Reserves |
| `0x80C1` | `RESERVES_ADD_OUTPUT` | Reserves |
| `0x80C3` | `RESERVES_REMOVE_OUTPUT` | Reserves |
| `0x80CB` | `COLLATERAL_INCREASE` | Collateral |
| `0x80CD` | `COLLATERAL_DECREASE` | Collateral |
| `0x80CF` | `COLLATERAL_STATUS` | Collateral |
| `0x808D` | `COLLATERAL_ATTESTATION` | Collateral |
| `0x809B` | `COLLATERAL_CONSENT_REQUEST` | Collateral |
| `0x809D` | `COLLATERAL_CONSENT_RESPONSE` | Collateral |
| `0x809F` | `COLLATERAL_LOCK` | Collateral |
| `0x80D1` | `DEPOSIT_OPEN` | Deposits |
| `0x80D3` | `DEPOSIT_CLOSE` | Deposits |
| `0x80D5` | `DEPOSIT_UPDATE` | Deposits |
| `0x80D7` | `DEPOSIT_KEY_ROTATE` | Deposits |
| `0x8097` | `QUORUM_ADD_MEMBER` | Quorum |
| `0x8099` | `QUORUM_REMOVE_MEMBER` | Quorum |
| `0x80AB` | `QUORUM_JOIN` | Quorum |
| `0x8031` | `RECEIVING_COSIGN_INVOICE` | Invoices |
| `0x8033` | `RECEIVING_CREDIT_PAYMENT` | Invoices |
| `0x8035` | `UNCREDITED_PAYMENT` | Invoices |
| `0x8041` | `SENDING_LOCK_PAYMENT` | Payments |
| `0x8043` | `SENDING_FAIL_PAYMENT` | Payments |
| `0x8045` | `SENDING_FULFILL_PAYMENT` | Payments |
| `0x80E1` | `ONCHAIN_CREDIT` | On-chain |
| `0x80E3` | `ONCHAIN_LOCK` | On-chain |
| `0x80E5` | `ONCHAIN_FAIL` | On-chain |
| `0x80E7` | `ONCHAIN_FULFILL` | On-chain |
| `0x80F1` | `TRANSFER_LOCK` | Transfer |
| `0x80F3` | `TRANSFER_COMPLETE` | Transfer |
| `0x80F5` | `TRANSFER_TIMEOUT` | Transfer |
| `0x8021` | `MAINTENANCE_FEE_COLLECT` | Maintenance |
| `0x801D` | `LEDGER_CLOSE` | Lifecycle |
| `0x8051` | `CHANNEL_CLOSE_TOMBSTONE` | Lifecycle |

---

## 9. Transfer Protocol

### 9.1 Flow

```
Sender                          Operator                        Receiver
  |                                |                               |
  |-- transfer_lock request ------>|                               |
  |                                |-- TransferLock(70) ---------> |
  |                                |   (locks source funds)        |
  |                                |                               |
  |                                |<-- transfer_complete request -|
  |                                |   (with preimage)             |
  |                                |                               |
  |                                |-- TransferComplete(71) ------>|
  |                                |   (credits destination)       |
  |                                |                               |
  OR on timeout:                   |                               |
  |                                |-- TransferTimeout(72) ------->|
  |                                |   (refunds source)            |
```

### 9.2 State Mutations

**TransferLock:**
- `source.balance -= (amount + fee)`
- `source.locked_balance += (amount + fee)`
- Creates `PendingTransfer` in `pending_transfers`

**TransferComplete:**
- Verifies `SHA256(preimage) == hash` (from completion script)
- `destination.balance += amount`
- `source.locked_balance -= (amount + fee)`
- Fee is consumed (exits circulation)
- Removes `PendingTransfer`

**TransferTimeout:**
- `source.balance += (amount + fee)`
- `source.locked_balance -= (amount + fee)`
- Removes `PendingTransfer`

### 9.3 Fee Calculation

**TransferFeeSchedule:**

```
fee = fixed_sats + (amount_sats * rate_bps / 10_000)
```

| Field | Type | Default |
|-------|------|---------|
| `fixed_sats` | `u64` | 2 sats |
| `rate_bps` | `u16` | 20 bps (0.20%) |

Maximum: `rate_bps <= 10000` (100%).

> Source: `types.rs:457-483`, `operation_validation.rs:372`

**FeeStructure** (periodic custody fees):

```
fee = (annualized_fixed * blocks_elapsed / BLOCKS_PER_YEAR)
    + (balance * annualized_bps * blocks_elapsed / (BLOCKS_PER_YEAR * 10_000))
```

Where `BLOCKS_PER_YEAR = 52560` (365.25 * 144).

| Field | Type | Default |
|-------|------|---------|
| `annualized_fixed` | `u64` | 0 sats |
| `annualized_bps` | `u16` | 0 bps |
| `frequency_blocks` | `u32` | 2016 (~2 weeks) |

> Source: `types.rs:401-445`

---

## 10. Quorum and Collateral

### 10.1 Two-Sided Trail

The operator funds 100% collateral by depositing on quorum member ledgers and locking those
funds. Adding a quorum member creates entries on both sides:

1. **Operator's ledger**: `QuorumAddMember` (disc=43) — records the member's pubkey and consent signature
2. **Member's ledger**: `QuorumJoin` (disc=46) — records that this operator joined the quorum

The operator then funds a deposit on the member's ledger (via `OnchainCredit`) and locks it
as collateral (via `CollateralLock`). This is operator capital — the quorum member contributes
no funds, only monitoring and dispute capability.

This two-sided trail ensures both parties have an auditable record of the relationship.

### 10.2 Collateral Attestation

A `CollateralAttestation` (disc=42) proves that operator-funded collateral is locked on a
quorum member's ledger:

| Field | Type | Description |
|-------|------|-------------|
| `operator_id` | `PublicKey` | Operator this attestation is for |
| `quorum_member` | `PublicKey` | Member who signed |
| `collateral_ledger_id` | `String` | Ledger where collateral is locked |
| `amount` | `u64` | Collateral amount (satoshis) |
| `block_height` | `u32` | Creation block height |
| `lock_until_block` | `u32` | Expiry block height |
| `signature` | `[u8; 64]` | Member's signature |
| `ledger_hash` | `[u8; 32]` | Member's ledger hash at time of attestation |

The `ledger_hash` field binds the attestation to the member's ledger state, preventing
attestation with stale or invalid state.

Attestations are per-operator (stored in `collateral_attestations: HashMap<PublicKey, CollateralAttestation>`).
Stale attestations (beyond `max_attestation_age_blocks`) do not count toward coverage.

> Source: `types.rs:819-843`

### 10.3 Ratchet Semantics

`CollateralLock` (disc=45) enforces ratchet semantics:

- Collateral amount can only **increase** (or stay the same)
- Lock expiry can only be **extended** (or stay the same)
- This prevents the locked operator funds from being silently reduced

### 10.4 Reserves Rotation

`ReservesRotate` (disc=12) moves reserves to a new UTXO with Taproot spend paths that include
quorum-controlled recovery paths. After rotation:

- All subsequent updates require a co-signature from a quorum member
- The `quorum_threshold` and `quorum_size` fields define the multisig parameters
- The `first_expiry_block` defines when the earliest quorum member's commitment expires

The `collateral_enforcement_block` in `LedgerOpen` defers collateral size requirements during
the bootstrap period, allowing the ledger to operate before a full quorum is assembled.

---

## 11. Dispute State Machine

### 11.1 State Diagram

```
                    CustodyDispute (54)
          ┌──────── (quorum member) ────────┐
          │                                 │
          ▼                                 │
    ┌──────────┐   QuorumAddMember(43)   ┌──────┐
    │ Disputed │   CollateralAttest(42)  │Normal│
    │          │◄── (quorum co-signs) ──►│      │
    └────┬─────┘                         └──────┘
         │                                  ▲
         │ CustodyArmed (57)                │
         ▼                                  │
    ┌──────────┐   CustodyAcquire (55)      │
    │  Armed   │────── (winner) ────────────┘
    │          │
    └────┬─────┘
         │ CustodyYield (56)
         │   (loser)
         ▼
    ┌──────────┐
    │Tombstoned│
    │          │
    └──────────┘
```

### 11.2 Transition Rules

| Current State | Allowed Operations | Blocked |
|--------------|-------------------|---------|
| **Normal** | All except 55 (CustodyAcquire), 56 (CustodyYield), 57 (CustodyArmed) | Dispute resolution ops |
| **Disputed** | 42 (CollateralAttestation), 43 (QuorumAddMember), 57 (CustodyArmed) | All normal operations |
| **Armed** | 55 (CustodyAcquire), 56 (CustodyYield) | Everything else |
| **Tombstoned** | None | All operations |

> Source: `types.rs:933-953` — `allows_operation()`

### 11.3 Signer Authorization

| Operation | Authorized Signer |
|-----------|------------------|
| `CustodyDispute` (54) | Any current quorum member (NOT the operator) |
| All other operations | `parent_pubkey` (the operator, or new custodian after CustodyAcquire) |

Non-operator updates (signed by someone other than `parent_pubkey`) are **rejected** — not
disputed, but refused entirely. The only exception is `CustodyDispute`, which must come from
a quorum member.

> Source: `ledger.rs:314-355` — `validate_update_signer()`

### 11.4 Entropy Selection

Winner selection uses a deterministic, unpredictable scoring function:

```
score(candidate) = SHA256(entropy_block_hash[32] || candidate_pubkey[33])
winner = candidate with lowest score (lexicographic comparison)
```

Properties:
- **Unpredictable** before the entropy block is mined
- **Deterministic** — every observer computes the same winner
- **Order-independent** — shuffling the candidate list doesn't change the result

Each candidate commits to a preimage via `HASH160(preimage)` in the `CustodyArmed` operation's
`commitment_hash` field before the entropy block is known.

> Source: `types.rs:956-992` — `entropy_selection_score()`, `select_entropy_winner()`

### 11.5 On-Chain Resolution

After entropy selection:

- **Winner**: builds and broadcasts a confiscation transaction spending the reserves, then
  publishes `CustodyAcquire` (disc=55) with the new reserves address and transaction details
- **Loser**: publishes `CustodyYield` (disc=56), tombstoning their branch

The winning candidate becomes the new operator with `parent_pubkey` updated to their key.

---

## 12. Nostr Transport

### 12.1 Event Kinds

| Kind | Type | Purpose |
|-----:|------|---------|
| 9100 | Regular | Ledger updates (signed hash chain entries) |
| 9101 | Regular | Requests (deposit_open, transfer_lock, cosign, etc.) |
| 9102 | Regular | Responses to requests |
| 9103 | Regular | Dispute events |
| 9104 | Regular | Recovery agreement events |
| 39100 | Parameterized replaceable (NIP-33) | Ledger advertisements |

> Source: `nostr.rs:63-90`

### 12.2 Tag Schema

**Kind 9100 (Ledger Update):**

| Tag | Value | Description |
|-----|-------|-------------|
| `d` | `{ledger_id}` | 64-char hex ledger identifier |
| `seq` | `{sequence_number}` | Update sequence number |
| `prev` | `{previous_hash}` | Hex-encoded previous hash |
| `hash` | `{current_hash}` | Hex-encoded current hash |

Content: Base64-encoded TLV of `SignedLedgerUpdate`.

**Kind 9101 (Request):**

| Tag | Value | Description |
|-----|-------|-------------|
| `l` | `{ledger_id}` | Target ledger (for relay-side filtering) |
| `action` | `{action_name}` | Request type |

Content: JSON with action parameters.

**Kind 9102 (Response):**

| Tag | Value | Description |
|-----|-------|-------------|
| `e` | `{request_event_id}` | Reference to originating request |
| `l` | `{ledger_id}` | Ledger identifier |
| `status` | `"ok"` or `"error"` | Result status |

Content: JSON with `{ success, result, error }`.

**Kind 9103 (Dispute):**

| Tag | Value | Description |
|-----|-------|-------------|
| `d` | `{ledger_id}` or compound fork key | Dispute identifier |
| `l` | `{ledger_id}` | For relay filtering |
| `reason` | `{reason_string}` | Dispute reason |
| `disputer` | `{pubkey_hex}` | Disputer's public key |

Content: JSON with `LedgerDispute` details.

**Kind 39100 (Advertisement):**

| Tag | Value | Description |
|-----|-------|-------------|
| `d` | `{ledger_id}` | Ensures only latest ad per ledger (NIP-33) |

Content: JSON with fees, limits, metadata.

### 12.3 Subscription and Polling

**Subscription strategy:**
- Per-ledger `#l` tag filtering for requests and disputes (relay-side, reduces bandwidth)
- Per-ledger `#d` tag filtering for updates
- Request lookback: 5 seconds (reduced from 30s to prevent EAGAIN relay disconnects)
- Dispute lookback: 30 seconds
- Response lookback: 120 seconds

**Polling fallback:**
- `fetch_recent_requests()` runs every 5 seconds
- Catches ~14% of events missed by subscription
- Uses per-ledger `#l` filter for efficiency

> Source: `nostr.rs:756+`

### 12.4 Request Actions

**Daemon-handled** (processed by `deposits-node run`):

| Action | Handler |
|--------|---------|
| `transfer_lock` | `process_transfer_lock_request()` |
| `transfer_complete` | `process_transfer_complete_request()` |
| `cosign_update` | `process_cosign_request()` |

**CLI-handled** (processed by `nostr watch`):

| Action | Purpose |
|--------|---------|
| `deposit_open` | Create deposit offer |
| `make_offer` | Accept deposit offer |
| `deposit_withdraw` | On-chain withdrawal |
| `collateral_lock` | Lock collateral |
| `custody_transfer_sign` | Sign custody transfer |
| `confiscation_sign` | Sign confiscation TX |
| `custodian_query` | Query custodian info |
| `lottery_reveal` | Reveal lottery preimage |

---

## 13. Persistence

### 13.1 JSONL Format

Each ledger is stored as a JSONL file at `wallet/ledgers/{ledger_id_hex}.jsonl`.

Line types (discriminated by `"type"` field):

```jsonl
{"type":"Role","role":"Operator"}
{"type":"State","ledger_id":"ab01...","sequence":42,...}
{"type":"Update","message":"...","sequence_number":0,...}
{"type":"Update","message":"...","sequence_number":1,...}
```

| Line Type | Semantics |
|-----------|-----------|
| `Role` | `LedgerRole` (Operator, Partner, Auditor). First line. Default: Partner |
| `State` | Full `LedgerState` snapshot. Last-seen State wins on load |
| `Update` | `SignedLedgerUpdate` entry. Deduplicated by `sequence_number` |

> Source: `handler.rs:47-57` — `LedgerLogRow`

### 13.2 Append-Only Strategy

Persistence uses an append-only strategy tracked by `persisted_update_counts: Mutex<HashMap<String, usize>>`:

1. **First save**: full rewrite — Role + State + all Updates
2. **Subsequent saves**: append a fresh State line + new Update lines only
3. **Compaction**: periodic full rewrite resets the counter

The fresh State line on each append is required because the loader takes the last-seen State.
Without it, quorum members, deposits, and other state fields would be stale.

> Source: `handler.rs:834-979`

### 13.3 Load and Replay

Loading follows this sequence:

1. Parse each line, classifying as Role, State, or Update
2. If no Role line, default to `Partner`
3. Take the **last-seen** State line as the base state
4. Deduplicate Update lines by `sequence_number` (using a `HashSet`)
5. Sort updates by sequence
6. Find `state_sequence` from the State line's sequence
7. Replay any updates with sequence > `state_sequence` via `apply_state_changes()`

Deduplication handles daemon/CLI races where both processes may write the same updates.
Trailing-character JSONL parse warnings from concurrent appends are benign and skipped.

> Source: `handler.rs:404-552`

---

## 14. Validation Rules

### 14.1 Global Invariants

Every valid ledger must maintain these invariants at all times:

1. **Hash chain integrity**: each update's `previous_hash` must equal the prior update's `current_hash`
2. **Signature authorization**: updates must be signed by `parent_pubkey` (except CustodyDispute by quorum member)
3. **Reserves coverage**: `reserves.amount >= sum(deposits.balance) / 1000`
4. **Non-negative available balance**: no deposit may have `locked_balance > balance`
5. **Contiguous sequences**: `history.len() - 1 == current_sequence`
6. **Final hash consistency**: last update's `current_hash == state.hash`
7. **Dispute state compliance**: each operation must be allowed by current `DisputeState`

### 14.2 Per-Operation Validation

| Operation | Key Validation Rules |
|-----------|---------------------|
| `ReservesIncrease` | `new_amount > current_amount` |
| `ReservesDecrease` | `new_amount < current_amount` AND `new_amount >= required_reserves()` |
| `ReservesRotate` | Reserves exist, quorum parameters valid |
| `DepositOpen` | Deposit ID must not already exist |
| `DepositClose` | `balance == 0`, `locked_balance == 0`, no active invoices |
| `DepositUpdate` | Deposit exists, `annualized_bps <= 10000` |
| `InvoiceLock` / `OnchainLock` | `available_balance() >= amount` |
| `TransferLock` | Source deposit exists, sufficient balance for `amount + fee` |
| `TransferComplete` | Transfer ID exists in `pending_transfers`, witness satisfies script |
| `TransferTimeout` | Transfer exists, `block_height >= timeout_height` |
| `CollateralLock` | Amount <= `deposit.balance`, ratchet enforced |
| `QuorumAddMember` | Valid member signature |
| `FeeCollect` | Fee matches formula, deposit has sufficient balance |
| `CustodyDispute` | Signer is current quorum member, state is Normal |

Reserves validation formula:

```
required_reserves = total_deposit_balance_msats / 1000
required_with_headroom = required_reserves + RESERVES_HEADROOM_SATS
```

> Source: `ledger.rs:366-445` — `validate_incoming_update()`, `ledger.rs:922-1133` — `validate_operation()`

### 14.3 Conformance Checking

The `LedgerConformanceValidator` performs full offline validation of a ledger export:

| Check | Method |
|-------|--------|
| Hash chain + sequence continuity | `validate_hash_chain()` |
| Signature validity count | `validate_signatures()` |
| State transition replay | `validate_state_transitions()` |
| Business rules (4 checks) | `validate_business_rules()` |

Conformance violations:

| Violation | Meaning |
|-----------|---------|
| `BrokenHashChain` | Hash chain integrity broken at a given sequence |
| `InvalidSignature` | Signature verification failed |
| `SequenceOutOfOrder` | Non-contiguous sequence numbers |
| `OperationFailed` | State transition failed to apply |
| `InsufficientReserves` | Reserves < deposits (with ratio) |
| `InsufficientCollateral` | Collateral < deposits (with ratio) |
| `StateHashMismatch` | Final computed hash differs from claimed |
| `OperatorMismatch` | Operator pubkey mismatch |
| `UncreditedPayment` | Payment settled without deposit credit issued |

> Source: `validation.rs:366-980`

---

## 15. Constants Reference

All constants from `deposits-core/src/constants.rs`:

| Constant | Value | Description |
|----------|------:|-------------|
| `DEPOSITS_PROTOCOL_VERSION` | 1 | Wire protocol version |
| `MIN_RESERVES_OUTPUT_SATS` | 660 | Minimum economically spendable reserves (sats) |
| `MAX_RESERVES_OUTPUT_SATS` | 1,000,000,000 | Maximum reserves (10 BTC) |
| `MIN_RESERVES_RATIO_PERCENT` | 100 | 100% reserve requirement |
| `DEFAULT_EMERGENCY_TIMEOUT_BLOCKS` | 144 | Default timeout (~1 day) |
| `MIN_EMERGENCY_TIMEOUT_BLOCKS` | 144 | Minimum timeout (~1 day) |
| `MAX_EMERGENCY_TIMEOUT_BLOCKS` | 4320 | Maximum timeout (~30 days) |
| `P2WSH_DUST_LIMIT_SATS` | 330 | Bitcoin Core P2WSH dust threshold |
| `P2WPKH_DUST_LIMIT_SATS` | 294 | Bitcoin Core P2WPKH dust threshold |
| `FEE_RATE_FLOOR_SAT_PER_VBYTE` | 3 | Minimum fee rate for calculations |
| `RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES` | 163 | Estimated weight to spend reserves output |
| `ESTIMATED_RESERVES_SPENDING_COST_SATS` | 489 | 163 vbytes * 3 sat/vb |
| `COLLATERAL_REPORTING_PERIOD_BLOCKS` | 144 | Between collateral changes (~1 day) |
| `RESERVES_HEADROOM_SATS` | 0 | Flat buffer on required reserves |
| `COLLATERAL_HEADROOM_SATS` | 1,000 | Flat buffer on required collateral |
| `STALE_ACK_THRESHOLD_SECS` | 30 | Max age for pending ACKs |
| `STALE_BROADCAST_THRESHOLD_SECS` | 5 | Max age before broadcast retry |
| `LAZY_SYNC_DELAY_SECS` | 2 | Delay before committing pending updates |
| `MAX_FEE_RATE_BPS` | 10,000 | Maximum fee rate (100%) |
| `BLOCKS_PER_YEAR` | 52,560 | 365.25 * 144 blocks/day |

> Source: `constants.rs:6-142`, `operation_validation.rs:372`, `types.rs:423`

---

## 16. Source Cross-Reference

| Type / Function | Location |
|----------------|----------|
| `SignedLedgerUpdate` | `deposits-core/src/types.rs:1414` |
| `LedgerState` | `deposits-core/src/types.rs:1013` |
| `Deposit` | `deposits-core/src/types.rs:591` |
| `DisputeState` | `deposits-core/src/types.rs:909` |
| `TransferFeeSchedule` | `deposits-core/src/types.rs:457` |
| `FeeStructure` | `deposits-core/src/types.rs:401` |
| `PendingTransfer` | `deposits-core/src/types.rs:554` |
| `CollateralAttestation` | `deposits-core/src/types.rs:819` |
| `QuorumMember` | `deposits-core/src/types.rs:805` |
| `QuorumMembership` | `deposits-core/src/types.rs:783` |
| `ReservesOutput` | `deposits-core/src/types.rs:732` |
| `DescriptorWitness` | `deposits-core/src/types.rs:338` |
| `DepositOffer` | `deposits-core/src/types.rs:2372` |
| `compute_ledger_id()` | `deposits-core/src/types.rs:1131` |
| `compute_deposit_id()` | `deposits-core/src/types.rs:217` |
| `compute_hash()` | `deposits-core/src/types.rs:1457` |
| `partner_signing_data()` | `deposits-core/src/types.rs:1485` |
| `operator_signing_data()` | `deposits-core/src/types.rs:1501` |
| `select_entropy_winner()` | `deposits-core/src/types.rs:980` |
| `entropy_selection_score()` | `deposits-core/src/types.rs:960` |
| `LedgerOperation` | `deposits-core/src/messages.rs:512` |
| `discriminant()` | `deposits-core/src/messages.rs:866` |
| TLV field constants | `deposits-core/src/messages.rs:2832` |
| Wire envelope types | `deposits-core/src/messages.rs:44` |
| `TlvStream` | `deposits-core/src/tlv.rs:149` |
| `TlvBuilder` | `deposits-core/src/tlv.rs:418` |
| `TlvReader` | `deposits-core/src/tlv.rs:546` |
| `write_varint()` | `deposits-core/src/tlv.rs:91` |
| `Ledger` | `deposits-core/src/ledger.rs:105` |
| `LedgerRole` | `deposits-core/src/ledger.rs:22` |
| `validate_incoming_update()` | `deposits-core/src/ledger.rs:366` |
| `validate_update_signer()` | `deposits-core/src/ledger.rs:314` |
| `validate_operation()` | `deposits-core/src/ledger.rs:922` |
| `apply_state_changes()` | `deposits-core/src/ledger.rs:1136` |
| `ValidationRules` | `deposits-core/src/validation.rs:25` |
| `LedgerConformanceValidator` | `deposits-core/src/validation.rs:434` |
| `sign_last_update()` | `deposits-node/src/node.rs:297` |
| `sign_and_broadcast()` | `deposits-node/src/node.rs:6665` |
| `operator_sign_persist_broadcast()` | `deposits-node/src/node.rs:376` |
| `request_cosign()` | `deposits-node/src/node.rs:6250` |
| Nostr kind constants | `deposits-node/src/nostr.rs:63` |
| `broadcast_ledger_update()` | `deposits-node/src/nostr.rs:706` |
| `send_ledger_request()` | `deposits-node/src/nostr.rs:820` |
| `LedgerLogRow` | `deposits-node/src/handler.rs:47` |
| `load_ledgers_from_jsonl()` | `deposits-node/src/handler.rs:404` |
| `persist_ledger_to_disk()` | `deposits-node/src/handler.rs:834` |
| Protocol constants | `deposits-core/src/constants.rs:6` |
| `MAX_FEE_RATE_BPS` | `deposits-core/src/operation_validation.rs:372` |
