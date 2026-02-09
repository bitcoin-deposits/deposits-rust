# Bitcoin Deposits Protocol

A two-layer protocol for custodial Bitcoin deposits with cryptographic accountability and multi-party dispute resolution.

## Overview

The protocol combines:
- **Ledger layer**: Off-chain state machine tracking deposits, payments, and fees
- **Collateral layer**: Multi-party custody with on-chain reserves backing

Each operator maintains a ledger backed by Bitcoin reserves. Deposits are credited/debited via signed operations forming a hash chain. Quorum members provide collateral backing and can dispute invalid operations.

## Core Concepts

### Ledger

A ledger tracks:
- **Deposits**: User balances keyed by public key
- **Reserves**: Bitcoin UTXO backing all deposits
- **Quorum**: Partner operators providing collateral
- **State**: Sequence number and hash chain

Every state change is a signed `LedgerOperation` appended to the ledger history.

### Ledger ID

Stable identifier computed as:
```
ledger_id = SHA256(operator_pubkey || reserves_address || genesis_block)
```

This survives custody transfers - the ledger ID stays constant even if the operator changes.

### Deposits

Each deposit has:
- `pubkey`: Unique identifier (depositor's key)
- `balance`: Available funds (millisatoshis)
- `locked_balance`: Funds locked for pending payments
- `fees`: Maintenance fee structure
- `last_fee_assessment`: Block height of last fee deduction

### Reserves

On-chain Bitcoin backing all deposits:
- Must cover 100% of deposit balances
- Stored in operator-controlled UTXO
- Spendable via Taproot with tiered timeouts

### Quorum

Partner operators who:
- Monitor ledger for invalid operations
- Provide collateral attestations
- Can initiate disputes if operator misbehaves

## Operations

### Ledger Lifecycle

| Operation | Purpose |
|-----------|---------|
| `LedgerOpen` | Initialize ledger with operator and reserves |
| `LedgerClose` | Terminate ledger operations |

### Reserves Management

| Operation | Purpose |
|-----------|---------|
| `ReservesIncrease` | Add funds to reserves |
| `ReservesDecrease` | Remove funds (must maintain coverage) |
| `ReservesRotate` | Migrate to new UTXO (e.g., P2WSH → P2TR) |

### Deposit Operations

| Operation | Purpose |
|-----------|---------|
| `DepositOpen` | Create new deposit with fee structure |
| `DepositClose` | Close deposit (must have zero balance) |
| `DepositUpdate` | Modify fee structure |

### Payment Operations

**Lightning payments:**
| Operation | Purpose |
|-----------|---------|
| `InvoiceCredit` | Credit deposit from received payment |
| `InvoiceLock` | Lock funds for outgoing payment |
| `InvoiceFulfill` | Complete payment (with preimage) |
| `InvoiceFail` | Cancel pending payment |

**On-chain payments:**
| Operation | Purpose |
|-----------|---------|
| `OnchainCredit` | Credit deposit from Bitcoin transaction |
| `OnchainLock` | Lock funds for withdrawal |
| `OnchainFulfill` | Complete withdrawal (with txid) |
| `OnchainFail` | Cancel pending withdrawal |

### Fee Operations

| Operation | Purpose |
|-----------|---------|
| `FeeCollect` | Deduct maintenance fees from deposit |

### Collateral Operations

| Operation | Purpose |
|-----------|---------|
| `QuorumAddMember` | Add partner to quorum |
| `QuorumRemoveMember` | Remove partner from quorum |
| `QuorumJoin` | Record membership in partner's ledger |
| `CollateralAttestation` | Partner proves collateral backing |
| `CollateralLock` | Deposit locks collateral for partner |

### Dispute Operations

| Operation | Purpose |
|-----------|---------|
| `CustodyDispute` | Quorum member declares invalid ledger |
| `CustodyArmed` | Candidate commits to custody race |
| `CustodyAcquire` | Winner claims reserves |
| `CustodyYield` | Loser acknowledges loss |

## Wire Protocol

### Signed Updates

Every operation is wrapped in a `SignedLedgerUpdate`:

```
SignedLedgerUpdate {
    message: Vec<u8>,           // Serialized operation
    message_type: u16,          // Operation discriminant
    operator_id: PublicKey,     // Signer
    ledger_id: [u8; 32],        // Target ledger
    sequence_number: u64,       // Sequential counter
    previous_hash: [u8; 32],    // Hash chain link
    current_hash: [u8; 32],     // State hash after operation
    operator_signature: [u8; 64], // Schnorr signature
}
```

### Hash Chain

Each operation extends the hash chain:
```
current_hash = SHA256(previous_hash || sequence_number || operation_bytes)
```

Genesis operation uses `previous_hash = [0; 32]`.

### Message Types

| Type | Kind | Purpose |
|------|------|---------|
| `LEDGER_UPDATE` | 0x8001 | Propose state change |
| `LEDGER_UPDATE_RESPONSE` | 0x8003 | Accept/reject change |
| `HANDSHAKE` | 0x8005 | Establish connection |
| `SYNC` | 0x8009 | Request missing updates |
| `RECOVERY` | 0x800D | Recovery voting/claims |
| `COORDINATION` | 0x8011 | Invoice cosigning, quorum requests |

## Nostr Transport

For public broadcasting and discovery:

| Kind | Purpose |
|------|---------|
| 9100 | Ledger updates (signed operations) |
| 9101 | Ledger requests (deposit_open, etc.) |
| 9102 | Ledger responses |
| 9103 | Disputes (quorum member only) |
| 9104 | Recovery agreement |
| 39100 | Ledger advertisement (replaceable) |

### Ledger Advertisement

Operators publish terms for wallet discovery:

```json
{
  "ledger_id": "abc123...",
  "operator_name": "Alice's Node",
  "annual_fee_bps": 100,
  "min_fee_sats": 1000,
  "fee_period_blocks": 2016,
  "max_deposit_sats": 10000000,
  "quorum_size": 3
}
```

### Request/Response Flow

1. Wallet publishes `KIND_LEDGER_REQUEST` with action and params
2. Operator watches for requests on their ledger
3. Operator processes request and applies operation
4. Operator publishes `KIND_LEDGER_RESPONSE` with result

## Fee Structure

Deposits incur maintenance fees:

```rust
FeeStructure {
    annualized_fixed: u64,    // Fixed annual fee (satoshis)
    annualized_bps: u16,      // Percentage (basis points)
    frequency_blocks: u32,    // Collection frequency
}
```

### Calculation

```
elapsed_blocks = current_block - last_fee_assessment
fixed_portion = (annualized_fixed * elapsed_blocks) / BLOCKS_PER_YEAR
percentage_portion = (balance * annualized_bps * elapsed_blocks) / (BLOCKS_PER_YEAR * 10000)
total_fee = fixed_portion + percentage_portion
```

Where `BLOCKS_PER_YEAR = 52560`.

### Validation

Proposed fees must meet operator minimums:
- `annualized_bps >= min_annual_bps`
- `fixed_per_period >= min_fixed_per_period`

Deposits with insufficient fees are rejected.

## Deposit Funding

### On-Chain Flow

1. Operator creates `DepositOffer` with funding address
2. User sends Bitcoin to funding address
3. Operator detects confirmed transaction
4. Operator broadcasts `OnchainCredit` operation
5. Deposit balance increases

### Deposit Offer

```rust
DepositOffer {
    operator_id: PublicKey,
    ledger_id: String,
    deposit_pubkey: PublicKey,
    funding_address: String,
    max_amount_sats: u64,
    min_amount_sats: u64,
    deadline_block: u32,
    fees: Option<FeeStructure>,
    operator_signature: [u8; 64],
}
```

The operator commits to crediting the deposit if funds arrive before the deadline.

## Collateral Model

### 100% + 100% Backing

- **Reserves**: 100% of deposits backed by operator's on-chain UTXO
- **Collateral**: 100% additional backing from quorum members

### Attestation Flow

1. Partner commits collateral on their own ledger
2. Partner signs `CollateralAttestation` proving the commitment
3. Operator records attestation in their ledger
4. Attestations refresh periodically (every 144 blocks)

### Collateral Lock

Depositors can lock collateral backing:
```rust
CollateralLock {
    deposit_pubkey: PublicKey,
    amount: u64,
    lock_until_block: u32,
    operator_id: PublicKey,  // Operator being backed
    deposit_holder_signature: [u8; 64],
}
```

Ratchet semantics: can only increase amount and duration.

## Dispute Resolution

### States

| State | Description |
|-------|-------------|
| `Normal` | Regular operation |
| `Disputed` | Quorum disbanded, limited operations |
| `Armed` | Candidates locked for lottery |
| `Tombstoned` | Branch terminated |

### Flow

1. **Detection**: Quorum member detects invalid operation
2. **Dispute**: Publishes `CustodyDispute` → state becomes `Disputed`
3. **Arming**: Candidates publish `CustodyArmed` with commitment hash
4. **Selection**: After 6 blocks, entropy block determines winner
5. **Claim**: Winner proves on-chain spend with `CustodyAcquire`
6. **Yield**: Losers publish `CustodyYield` → branch `Tombstoned`

### Entropy Selection

Winner selected by:
```
candidates = sorted(armed_candidates)
entropy = SHA256(entropy_block_hash || candidates)
winner_index = entropy % len(candidates)
```

The entropy block must be at least 6 blocks after the latest `CustodyArmed`.

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MIN_RESERVES_SATS` | 660 | Economic spendability |
| `MAX_RESERVES_SATS` | 10 BTC | Sanity limit |
| `BLOCKS_PER_YEAR` | 52560 | Fee calculation |
| `COLLATERAL_PERIOD` | 144 blocks | Attestation frequency |
| `EMERGENCY_TIMEOUT` | 144 blocks | Unilateral spend delay |

## Security Model

### Cryptographic Guarantees

- **Hash chain**: Tamper-evident operation history
- **Signatures**: Every operation signed by operator
- **Taproot**: Multi-sig reserves with tiered timeouts

### Trust Assumptions

- Operator controls reserves honestly (or quorum disputes)
- Quorum members monitor and attest honestly
- Bitcoin blockchain provides finality

### Dispute Protection

If operator misbehaves:
1. Any quorum member can initiate dispute
2. Entropy-based lottery selects new custodian
3. New custodian must prove on-chain control
4. Depositors' funds protected by collateral backing

## Example Flows

### Open Deposit and Fund

```
1. Wallet → Operator: deposit_open request
2. Operator: Creates DepositOpen operation, signs, broadcasts
3. Operator → Wallet: Response with deposit_pubkey
4. Operator: Creates DepositOffer with funding_address
5. Wallet: Sends BTC to funding_address
6. Operator: Detects confirmed TX
7. Operator: Creates OnchainCredit operation
8. Result: Deposit has balance, fees structure set
```

### Collect Fees

```
1. Node: Checks current_block vs last_fee_assessment
2. Node: Calculates fee due based on FeeStructure
3. Node: Creates FeeCollect operation if fee > 0
4. Node: Signs and broadcasts operation
5. Result: Deposit balance reduced, last_fee_assessment updated
```

### Initiate Dispute

```
1. Quorum member: Detects invalid operation
2. Quorum member: Publishes CustodyDispute on Nostr
3. Ledger: Transitions to DISPUTED state
4. Candidates: Publish CustodyArmed with commitments
5. Ledger: Transitions to ARMED state
6. Wait: 6+ blocks for entropy
7. Winner: Spends reserves, publishes CustodyAcquire
8. Losers: Publish CustodyYield
9. Result: New custodian controls ledger
```
