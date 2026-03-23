# Bitcoin Deposits Protocol

A collateral-secured network of verifiable ledgers providing fast, scalable, key-controlled Bitcoin funds off-chain.

## Overview

The protocol combines:
- **Ledger layer**: Append-only hash chains of signed updates tracking deposits, transfers, and fees
- **Collateral layer**: Operator capital locked on quorum member ledgers, confiscable upon misbehavior
- **Reserves layer**: On-chain UTXO backing all obligations, spendable by quorum majority

Each operator maintains a ledger backed by Bitcoin reserves. Deposits are credited and debited via co-signed operations forming a hash chain. Quorum members provide collateral backing and can dispute invalid operations. Wallets verify the chain, retain evidence, and escalate through the quorum if the operator misbehaves.

Explicit tradeoffs:
- No unilateral exit: when operators fail, funds stay in the network under a new custodian
- No privacy: verification requires transparency
- Intermittent availability: a deposit is only as available as its operator

See [WHITEPAPER.md](WHITEPAPER.md) for design rationale.

## Core Concepts

### Ledger

A ledger is an immutable chain of updates, each containing the hash of the previous update and signed by the operator. After quorum establishment, updates are also co-signed by a quorum member. Different update types have different rules governing when and how they can be used. Ledgers are self-descriptive: their updates are publicly available and non-repudiable, allowing anyone to evaluate conformance.

A ledger tracks:
- **Deposits**: Account balances keyed by deposit ID
- **Reserves**: On-chain UTXO backing all obligations
- **Quorum**: Partner operators providing collateral and co-signatures
- **State**: Sequence number, hash chain, and causal ordering

### Ledger ID

Stable identifier computed as:
```
ledger_id = SHA256(operator_pubkey || reserves_address || genesis_block)
```

This survives custody transfers -- the ledger ID stays constant even if the operator changes.

### Deposits

A deposit is a balance controlled by a miniscript descriptor. The deposit ID is derived from the descriptor:

```
deposit_id = SHA256(descriptor)[0..16]
```

The descriptor is a miniscript policy string. The common case is `pk(<compressed_pubkey_hex>)` for single-key deposits, but any valid miniscript is supported: `multi()`, `and()`, `or()`, time locks, hash locks, etc. Operations are authorized by providing a witness satisfying the descriptor. (DEP-08)

Each deposit has:
- `deposit_id`: 16-byte identifier derived from descriptor
- `descriptor`: Miniscript spending policy
- `balance`: Available funds (millisatoshis)
- `locked_balance`: Funds locked for pending transfers/payments
- `fees`: Periodic custody fee schedule
- `transfer_fees`: Per-transfer fee schedule
- `is_collateral`: Whether this deposit holds operator capital for collateral
- `receive_requires_sig`: Whether incoming funds require a descriptor witness

### Reserves

On-chain Bitcoin backing all obligations. After quorum establishment, reserves are held in a Taproot UTXO with tiered spending paths (DEP-03):

1. **Full quorum** (k-of-n): No timelock. Normal operating path.
2. **Degraded quorum** (k-1 of n): Available before `quorum_expiry`. Allows rotation if one member disappears.
3. **Operator solo**: Available well after `quorum_expiry`. Last resort when the entire quorum is unresponsive.

### Quorum

Partner operators who:
- Co-sign ledger updates (providing causal ordering across ledgers)
- Monitor ledger for non-conforming operations
- Hold operator collateral on their own ledgers
- Can initiate disputes and confiscate collateral if the operator misbehaves

## Operations

Every state change is a signed `LedgerUpdate` appended to the hash chain. Operations are grouped by category.

### Lifecycle

| Disc | Operation | Purpose |
|------|-----------|---------|
| 1 | `LedgerOpen` | Initialize ledger with operator and reserves |
| 60 | `LedgerClose` | Terminate ledger operations |

### Quorum

| Disc | Operation | Purpose |
|------|-----------|---------|
| 12 | `QuorumBegin` | Establish/refresh quorum multisig and rotate reserves |
| 43 | `QuorumAddMember` | Add partner to quorum with terms |
| 44 | `QuorumRemoveMember` | Remove partner from quorum |
| 46 | `QuorumJoin` | Record membership on partner's own ledger |

### Deposits

| Disc | Operation | Purpose |
|------|-----------|---------|
| 20 | `DepositOpen` | Create deposit with descriptor and fee schedule |
| 21 | `DepositClose` | Close deposit (must have zero balance) |
| 23 | `DepositKeyRotate` | Change deposit descriptor (authorized by current descriptor) |

### Fees

| Disc | Operation | Purpose |
|------|-----------|---------|
| 22 | `FeeChange` | Modify fee schedule (with notice period) |
| 50 | `FeeCollect` | Deduct periodic fees from deposit |

### Lightning Payments

| Disc | Operation | Purpose |
|------|-----------|---------|
| 30 | `InvoiceCredit` | Credit deposit from received lightning payment |
| 31 | `InvoiceLock` | Lock funds for outgoing lightning payment |
| 32 | `InvoiceFail` | Cancel pending lightning payment |
| 33 | `InvoiceFulfill` | Complete lightning payment (with preimage) |

### On-chain Payments

| Disc | Operation | Purpose |
|------|-----------|---------|
| 35 | `OnchainCredit` | Credit deposit from confirmed transaction |
| 36 | `OnchainLock` | Lock funds for on-chain withdrawal |
| 37 | `OnchainFail` | Cancel pending withdrawal |
| 38 | `OnchainFulfill` | Complete withdrawal (with txid) |

### Transfers

| Disc | Operation | Purpose |
|------|-----------|---------|
| 70 | `TransferLock` | Lock funds with miniscript spending condition |
| 71 | `TransferComplete` | Complete transfer (witness satisfies condition) |
| 72 | `TransferFail` | Cancel transfer after timeout |

### Collateral

| Disc | Operation | Purpose |
|------|-----------|---------|
| 42 | `CollateralAttestation` | Partner proves collateral lock on their ledger |
| 45 | `CollateralLock` | Lock deposit funds as collateral backing |

### Dispute

| Disc | Operation | Purpose |
|------|-----------|---------|
| 54 | `DisputeEnter` | Quorum member declares non-conforming ledger |
| 55 | `DisputeAcquire` | Lottery winner claims custody |
| 56 | `DisputeYield` | Lottery loser yields |
| 57 | `DisputeArmed` | Candidate commits to custody lottery |

### Delivery

| Disc | Operation | Purpose |
|------|-----------|---------|
| 80 | `DeliveryEmbed` | Quorum member anchors unprocessed request hash |

Full wire format: DEP-02. On-chain transactions: DEP-03.

## Wire Protocol

### Signed Ledger Update

Every operation is wrapped in a TLV-encoded signed update (DEP-02):

| Type | Name | Description |
|------|------|-------------|
| 0 | message | Inner operation (TLV-encoded) |
| 2 | message_type | Operation discriminant |
| 4 | operator_id | Operator's compressed secp256k1 pubkey |
| 6 | ledger_id | Ledger identifier hash |
| 8 | sequence_number | Monotonically increasing counter (u64 LE) |
| 10 | previous_hash | Chain hash of the previous update |
| 16 | cosign_signature | Schnorr co-signature from quorum member |
| 18 | operator_signature | Schnorr signature from operator |
| 20 | block_height | Block height at creation |
| 22 | block_hash | Block hash at creation |
| 24 | cosigner_pubkey | Co-signing quorum member's pubkey |
| 26 | member_ledger_hash | Co-signer's ledger tip hash (causal ordering) |

### Hash Chain

```
current_hash = SHA256(
    sequence_number (8 LE)
    || previous_hash (32)
    || message (variable)
    [|| member_ledger_hash (32)]
    [|| cosign_signature (64)]
)

chain_hash = SHA256(current_hash (32) || operator_signature (64))
```

The operator signs `current_hash`. Their signature is folded into `chain_hash`, which becomes the next update's `previous_hash`. Both signatures are committed without circularity. After `QuorumBegin`, `member_ledger_hash` and `cosign_signature` are mandatory.

### Causal Ordering

Co-signatures include the co-signer's own ledger tip hash (`member_ledger_hash`). This hash is incorporated into `current_hash`, creating a web of causality across ledgers. When operator A's chain includes a co-signature referencing member B's chain at sequence N, it proves A's update happened after B's update N. This enables fraud proofs without relying on wall-clock time.

### Signing

All signatures use BIP-340 Schnorr.

**Co-signer**: signs a tagged hash over the update content and their ledger tip:
```
tag = SHA256("deposits/cosign")
digest = SHA256(tag || tag || message || message_type (2 LE)
    || sequence_number (8 LE) || previous_hash || member_ledger_hash)
```

**Operator**: signs after `current_hash` is finalized:
```
sig_input = SHA256(sequence_number (8 LE) || previous_hash
    || current_hash || message)
```

## Nostr Transport

All communication uses Nostr relays: operator relays for ephemeral request/response traffic, and ledger relays for durable event storage. (DEP-04)

### Event Kinds

| Kind | Name | Persistence | Description |
|------|------|-------------|-------------|
| 9100 | Ledger Update | Durable | Signed ledger update (base64 TLV) |
| 9101 | Fraud Proof | Durable | Fraud proof broadcast |
| 9103 | Dispute | Durable | Custody dispute notification |
| 9104 | Recovery Agreement | Durable | Quorum member recovery agreement |
| 9105 | Delivery Escalation | Durable | Wallet escalation of unprocessed request |
| 20101 | Request | Ephemeral | Wallet-to-operator request |
| 20102 | Response | Ephemeral | Operator-to-wallet response |
| 39100 | Advertisement | Replaceable | Operator terms (NIP-33) |
| 39101 | Price Oracle | Replaceable | BTC/USD price (NIP-33) |
| 39102 | Courier Advertisement | Replaceable | Courier capacity and fees (NIP-33) |

### Request Actions

| Action | Description | See |
|--------|-------------|-----|
| deposit_open | Open a new deposit | DEP-08 |
| make_offer | Create on-chain funding offer | DEP-10 |
| make_invoice | Create lightning invoice | DEP-10 |
| pay_invoice | Pay lightning invoice from deposit | DEP-10 |
| withdraw | On-chain withdrawal | DEP-10 |
| transfer_lock | Lock funds for transfer | DEP-09 |
| transfer_complete | Complete a transfer | DEP-09 |
| balance_query | Query deposit balance | DEP-08 |
| cosign_update | Request co-signature on update | DEP-02 |
| cosign_offer | Request co-signature on offer | DEP-10 |
| cosign_invoice | Request co-signature on invoice | DEP-10 |
| partner_add | Add quorum member | DEP-05 |
| partner_join | Record quorum join | DEP-05 |
| collateral_lock | Lock collateral | DEP-05 |
| collateral_record | Record collateral attestation | DEP-05 |
| request_route | Request cross-ledger route from courier | DEP-13 |

### Advertisements (Kind 39100)

Operators publish NIP-33 replaceable events advertising their terms. Content includes: operator name and pubkey, reserves and obligations, fee schedules (periodic and transfer), deposit limits, relay URL, and collateral enforcement block.

### Offline Operation

Wallets need no persistent connections. They can go offline indefinitely and catch up by replaying Kind 9100 events from any relay. The hash chain provides integrity verification regardless of when events are fetched.

## Transfers

The basic form of transfer is a two-phase operation between deposits on the same ledger. (DEP-09)

### Lock Phase

A deposit issues a `TransferLock` request specifying:
- Source and destination deposit IDs
- Amount and transfer fee
- A miniscript `completion_script` (spending condition)
- A `timeout_height` (block height deadline)
- A `nonce` (32 random bytes, also used for fraud proof embedding)
- A witness satisfying the sender's descriptor

If authorized, funds move from the sender's available balance to `locked_balance`.

### Completion

If the spending condition is satisfied before the timeout (via `TransferComplete` with a satisfying `script_witness`), funds move to the recipient minus the operator's transfer fee. If the timeout is reached (`TransferFail`), funds return to the sender minus a smaller timeout fee.

### Completion Scripts

Common patterns:
- **HTLC**: `sha256(H)` -- recipient provides preimage. Basis for cross-ledger and lightning-compatible transfers.
- **Signature**: `pk(key)` -- recipient signs the transfer_id
- **Timelock**: `and(pk(key), after(N))` -- key plus minimum block height
- **Multi-party**: `multi(2, key1, key2)` -- multiple signers

Any valid miniscript is supported.

### Timeout Limits

The `timeout_height` must not exceed `block_height + max_transfer_timeout_blocks` (per-quorum parameter, default 1008 blocks / ~1 week).

## Fee Structure

### Periodic Custody Fees

Deposits incur maintenance fees (DEP-07):

```
FeeStructure {
    annualized_msats: u64,    // Fixed annual fee (millisatoshis)
    annualized_bps: u16,      // Proportional fee (basis points/year)
    frequency_blocks: u32,    // Collection period (blocks)
}
```

Calculation per collection period:
```
fixed_portion = annualized_msats * blocks_elapsed / 52560
proportional_portion = balance * annualized_bps * blocks_elapsed / (52560 * 10000)
total_fee = fixed_portion + proportional_portion
```

### Per-Transfer Fees

Each transfer out of a deposit incurs:

```
TransferFeeSchedule {
    fixed_msats: u64,    // Fixed fee per transfer
    rate_bps: u16,       // Proportional fee (basis points)
}
```

### Fee Changes

Fee schedules are negotiated at deposit opening. Changes are governed by:
- `fee_change_after_blocks`: Minimum blocks after opening before any change
- `fee_change_notice_blocks`: Blocks of notice before a change takes effect
- `fee_change_limit_bps`: Maximum change per adjustment (basis points of current fee)

### Fee Minimums

Quorum members set fee minimums at join time. The operator cannot open deposits with fees below the strictest member's minimums, protecting members from inheriting unprofitable obligations after custody transfer.

## Payment Channels

Deposits receive and send funds through on-chain transactions and lightning payments. After quorum establishment, offers and invoices are co-signed by a quorum member and retained by the wallet as evidence. (DEP-10)

### On-chain Funding

1. Operator creates a co-signed funding offer with a bitcoin address and deadline
2. User sends Bitcoin to the funding address
3. Operator detects confirmed transaction, appends `OnchainCredit`

### Lightning

1. Operator creates a co-signed BOLT11 invoice on behalf of a deposit
2. When payment arrives (preimage obtained), operator appends `InvoiceCredit`
3. For outgoing payments: `InvoiceLock` -> route payment -> `InvoiceFulfill`/`InvoiceFail`

### Self-Pay

When the payer and payee are deposits on the same operator, the operator may settle internally without routing through lightning, avoiding routing fees and failure modes.

### Evidence Retention

Wallets retain co-signed offers and invoices as evidence. Without retention, the wallet cannot prove fraud. On-chain fraud proofs are constructed autonomously; lightning fraud proofs require the payer to provide the preimage.

## Collateral Model

Collateral is the operator's own capital, deposited and locked on quorum member ledgers. If the operator misbehaves, members confiscate the collateral. (DEP-05)

### Flow

1. Operator opens a collateral deposit (`is_collateral: true`) on each member's ledger
2. Operator funds and locks the deposit via `CollateralLock`
3. Member returns a signed attestation confirming the lock
4. Operator publishes `CollateralAttestation` on their own ledger

### Obligation Limits

A ledger's total obligations must not exceed the least of:

1. The reserves amount (from `QuorumBegin`)
2. The sum of all attested collateral (`total_collateral` from `QuorumBegin`)
3. Twice the smallest `collateral_lock_amount` across all quorum members

Enforced when creating new funding offers or invoices. The `total_collateral` field on `QuorumBegin` gives wallets a single co-signed value to check against.

### Security Arithmetic

With a 3-member quorum where each member holds collateral C:
- Total collateral at risk: 3C
- Maximum obligations: 2C (from limit #3)
- A theft yields at most 2C but costs 3C -- the attack costs 1.5x what it gains

### QuorumBegin

Once members are added, the operator rotates reserves into a new Taproot multisig UTXO. `QuorumBegin` (disc 12) records the new reserves address, quorum members, `quorum_expiry` (shortest collateral lock), and `total_collateral`. After `QuorumBegin`, co-signatures become mandatory. A new `QuorumBegin` must be appended before `quorum_expiry`. (DEP-03, DEP-05)

The reserves rotation transaction includes an `OP_RETURN` output with the `chain_hash` at the `QuorumBegin` sequence, giving wallets an on-chain anchor to verify ledger state.

### Member Terms

Each member specifies at join time (via `QuorumAddMember`):
- Fee minimums: `min_fee_bps`, `min_fee_fixed`, `max_fee_period`
- Collateral requirements: `collateral_lock_amount`, `collateral_lock_until`
- Timing obligations: `dispute_response_blocks`, `dispute_arm_blocks`, `service_response_blocks`, `max_transfer_timeout_blocks`
- Descriptor limit: `max_descriptor_bytes`

The strictest values across all members apply to the quorum.

## Fraud Proofs

Fraud proofs are constructed by embedding a proof hash into a ledger chain, then broadcasting the evidence with a causal chain linking the hash to the accused operator. (DEP-06)

### Types

1. **Uncredited on-chain payment**: Operator saw sufficient confirmations but did not credit the deposit. Wallet constructs this autonomously.
2. **Uncredited lightning payment**: Operator created a cosigned invoice, received payment (proved by preimage), but did not credit the deposit. Requires payer cooperation.
3. **Stale co-signature**: A co-signer's `member_ledger_hash` precedes their own later hash -- proving they backdated their attestation.
4. **Inactive quorum member**: A member was active but did not initiate a dispute within the required block window after embedded fraud evidence.
5. **Non-conforming update**: Operator signed an update that violates protocol rules.

### Construction

```
tag = SHA256("deposits/fraud_proof")
proof_hash = SHA256(tag || tag || proof_type || accused_pubkey
    || ledger_id || evidence_bytes)
```

The `proof_hash` is embedded as the `nonce` field in a self-transfer. Once the operator signs an update containing this hash, the evidence is causally ordered.

### Broadcast

A fraud broadcast (Kind 9101) contains the hashable evidence, the embedding location, and a causal chain of co-signed updates linking the embedding to the accused ledger.

## Delivery Escalation

When an operator ignores a wallet's request, the wallet can escalate through quorum members. (DEP-12)

1. **Direct request**: Wallet publishes Kind 20101 to operator's relay (normal flow)
2. **Durable publication**: Wallet re-publishes as Kind 9105 (durable record)
3. **Quorum member delivery**: Wallet pays a member to append `DeliveryEmbed` (disc 80) on their ledger, anchoring the request hash
4. **Clock starts**: `service_response_blocks` begins at the embed's `block_height`. If the operator's ledger advances past the deadline without processing the request, the censorship proof is complete.

The member's embedding fee is the small guaranteed payoff. The large contingent payoff is collateral confiscation if the delivery reveals genuine censorship.

## Couriers

Transfers move funds between deposits on the same ledger. To move funds across ledgers, wallets use couriers -- services that hold deposits on multiple ledgers and carry transfers between them via HTLCs. (DEP-13)

### Flow

1. Wallet locks funds to the courier's deposit on ledger A (hash lock)
2. Courier locks funds from its deposit on ledger B to the wallet's deposit on B (same hash lock)
3. Wallet reveals preimage on B, claiming funds
4. Courier observes preimage, completes transfer on A

The courier's outbound timeout is strictly earlier than the inbound timeout, ensuring that if the wallet never reveals, both locks expire and neither party loses funds.

### Fees

Couriers set per-ledger directional fees:
- **fee_out**: operator transfer fee + courier margin (sending from a ledger)
- **fee_in**: courier margin (receiving on a ledger)

Route cost: `fee_out(source) + fee_in(destination)`.

### Discovery

Couriers advertise via Kind 39102 (NIP-33 replaceable) on the ledger relay: which ledgers they bridge, available balance per ledger, and directional fees. Wallets compare and select based on fee, liquidity, or coverage.

## Dispute Resolution

When a quorum member detects fraud, they initiate a dispute to transfer custody. (DEP-06)

### States

| State | Description |
|-------|-------------|
| `Normal` | Regular operation, all operations allowed |
| `Disputed` | Quorum disbanded, limited operations |
| `Armed` | Candidates committed to lottery |
| `Tombstoned` | Branch terminated |

### Lottery

1. **Commitment**: Each participating member appends `DisputeArmed` with `commitment_hash` (HASH160 of a secret preimage) and `target_reserves` address. Members must arm within `dispute_arm_blocks`.
2. **Entropy**: An entropy block is selected -- the first block mined after all participants have armed.
3. **Reveal**: Each participant reveals their preimage. Winner: `score = SHA256(preimage || entropy_block_hash)`, lowest score wins.
4. **Settlement**: Winner spends reserves to their `target_reserves`, appends `DisputeAcquire`, establishes new quorum. Losers append `DisputeYield`.

### Respectful vs Punitive

**Respectful** (unavailability without proven fraud):
- Only the amount covering obligations goes to the winner
- Change returned to the original operator's pubkey
- Collateral unaffected

**Punitive** (proven non-conformance):
- Full reserves go to the winner
- Excess above obligations split among quorum members
- Collateral on other ledgers may be confiscated

### Dispute State Machine

| Current State | Allowed Operations | Next State |
|---------------|-------------------|------------|
| `Normal` | All except dispute ops | `Normal` |
| `Normal` | `DisputeEnter` | `Disputed` |
| `Disputed` | `QuorumAddMember`, `CollateralAttestation` | `Disputed` |
| `Disputed` | `DisputeArmed` | `Armed` |
| `Armed` | `DisputeAcquire` | `Normal` |
| `Armed` | `DisputeYield` | `Tombstoned` |
| `Tombstoned` | None | `Tombstoned` |

## Time Obligations

All times are measured in block height against the base layer. (DEP-11)

### Provable Obligations

| Event | Deadline | Evidence |
|-------|----------|----------|
| On-chain credit | Operator signs past `deadline_block` without credit | Cosigned offer + signed update |
| Lightning credit | Preimage exists, no credit | Cosigned invoice + preimage |
| Transfer timeout | Operator signs past `timeout_height` with funds locked | TransferLock + signed update |
| Request processing | Operator signs past embed + `service_response_blocks` | DeliveryEmbed + signed update |
| Quorum rotation | Operator signs past `quorum_expiry` without new quorum | Signed update |
| Dispute response | Member active after evidence + `dispute_response_blocks` | Fraud proof + member updates |
| Collateral lock | Reduced before `lock_until_block` | CollateralLock + withdrawal |

### Advisory Obligations

| Event | Consequence |
|-------|-------------|
| Fee collection | Operator loses revenue; members may decline to co-sign |
| Co-sign timeliness | Unresponsive members excluded from next quorum |
| Evidence retention | Wallet cannot prove fraud without evidence |

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `BLOCKS_PER_YEAR` | 52560 | Fee calculation |
| `MIN_RESERVES_SATS` | 660 | Economic spendability |
| `MAX_RESERVES_SATS` | 10 BTC | Sanity limit |

### Per-Quorum Parameters

| Parameter | Suggested Default | Purpose |
|-----------|-------------------|---------|
| `dispute_response_blocks` | 144 (~1 day) | Member must respond to fraud evidence |
| `dispute_arm_blocks` | 144 (~1 day) | Window to arm for lottery after dispute |
| `service_response_blocks` | 72 (~12 hours) | Unprocessed request becomes provable censorship |
| `max_transfer_timeout_blocks` | 1008 (~1 week) | Maximum transfer lock duration |

## Security Model

### Economic Deterrence

Quorum members are incentivized predators. They earn basis points on co-signing fees during normal operation, but stand to confiscate the operator's entire collateral deposit on their ledger if the operator misbehaves. This asymmetry -- steady small income versus a one-time windfall worth orders of magnitude more -- ensures active monitoring without protocol-level enforcement.

### Trust Assumptions

- Operator controls reserves honestly (or quorum disputes)
- Quorum members monitor and attest honestly (or face collateral confiscation on their own ledgers)
- Bitcoin blockchain provides finality and entropy
- The only failure mode is unanimous quorum collusion, which the collateral web makes more expensive than the value at risk

### Lightning Trust Boundary

Lightning invoice fraud is not autonomously provable -- the operator's lightning node is a trust boundary the protocol cannot fully bridge. However, any payer might provide the preimage to the wallet, and one confirmed theft triggers dispute, reserves seizure, and collateral confiscation. The upside of stealing a single payment is bounded; the downside is existential.

## DEP Index

| DEP | Title |
|-----|-------|
| [DEP-01](DEP-01.md) | DEP Purpose and Guidelines |
| [DEP-02](DEP-02.md) | Ledger State Model |
| [DEP-03](DEP-03.md) | On-Chain Transactions |
| [DEP-04](DEP-04.md) | Peer Messaging |
| [DEP-05](DEP-05.md) | Quorum and Collateral |
| [DEP-06](DEP-06.md) | Fraud Proofs and Recovery |
| [DEP-07](DEP-07.md) | Fee Schedules |
| [DEP-08](DEP-08.md) | Deposits |
| [DEP-09](DEP-09.md) | Transfers |
| [DEP-10](DEP-10.md) | Payment Channels |
| [DEP-11](DEP-11.md) | Time Obligations |
| [DEP-12](DEP-12.md) | Delivery Escalation |
| [DEP-13](DEP-13.md) | Couriers |
