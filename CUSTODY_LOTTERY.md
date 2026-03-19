# Custody Lottery: On-Chain Dispute Resolution

## Overview

When multiple operators dispute custody of a ledger, the winner must be selected fairly. The current implementation uses off-chain entropy (block hash) with signature coordination. This document describes an on-chain lottery mechanism where the Bitcoin script itself determines the winner.

## Problem

Current flow:
1. Disputants arm for entropy selection
2. Wait for entropy block
3. Off-chain calculation determines winner
4. Quorum members sign custody transfer to winner
5. Winner broadcasts DisputeAcquire

Issues:
- Quorum must coordinate to sign for the "correct" winner
- Relies on off-chain agreement about who won
- Winner must collect threshold signatures

## Solution: Preimage Size Lottery

Use committed preimages where the SIZE of each preimage contributes entropy. No party can predict others' choices, making the outcome fair.

### Entropy Mechanism

Each disputant:
1. Chooses a secret preimage of length 17 to 16+N bytes (where N = number of disputants)
2. Commits `HASH160(preimage)` in their DisputeArmed message
3. After confiscation tx confirms, reveals preimage via Nostr

Winner calculation:
```
contribution_i = LEN(preimage_i) - 16    // value 1 to N
total = sum(all contributions)
winner_index = total % N
```

Since each party commits their hash before seeing others' commitments, and preimage size is hidden until reveal, no party can manipulate the outcome.

## Protocol Flow

### Phase 1: Dispute & Arm

```
Operator A: DisputeEnter { reason: "..." }
Operator B: DisputeEnter { reason: "..." }
Operator C: DisputeEnter { reason: "..." }

Operator A: DisputeArmed {
    commitment_hash: HASH160(preimage_a),  // 20 bytes
    target_reserves: "bcrt1p...",          // winner destination
}
... (B and C also arm)
```

### Phase 2: Confiscation

Quorum builds and signs a confiscation transaction:
- **Input**: Current Taproot reserves (threshold signature from quorum)
- **Output**: Lottery script encoding all disputants' hashes and pubkeys

The quorum doesn't decide the winner - they just move funds to the lottery output.

### Phase 3: Reveal

After confiscation tx confirms, disputants reveal preimages via Nostr:

```
custody_lottery_reveal {
    ledger_id: "...",
    preimage: "deadbeef...",  // 17-20 bytes hex
}
```

All disputants should reveal. If someone doesn't reveal, see "Non-Revelation" below.

### Phase 4: Winner Claims

Anyone can calculate the winner from revealed preimages. The winner builds a claim transaction:

- **Input**: Lottery output
- **Witness**: `<winner_sig> <preimage_1> <preimage_2> ... <preimage_n>`
- **Output**: Winner's target_reserves address

The script verifies:
1. Each preimage hashes to the committed hash
2. Each preimage is valid length (17 to 16+N)
3. Winner calculation matches the signer's index

### Phase 5: DisputeAcquire

Winner publishes DisputeAcquire with the claim txid, completing custody transfer.

## Script Construction

### Taproot Structure

```
Lottery Output (Taproot):
├── Key path: NUMS (disabled)
├── Leaf 0: Lottery claim (preimage reveal + winner sig)
├── Leaf 1: Recovery - quorum minus operator, threshold T, CSV 144 blocks
├── Leaf 2: Recovery - quorum minus operator, threshold T-1, CSV 1008 blocks
└── Leaf 3: Recovery - quorum minus operator, threshold T-2, CSV 4032 blocks
```

### Lottery Script (Tapscript)

For N disputants, the script verifies preimages and calculates winner:

```
// Stack: <sig> <preimage_n> ... <preimage_2> <preimage_1>

// Verify preimage 1 and extract size contribution
OP_DUP OP_HASH160 <hash_1> OP_EQUALVERIFY
OP_SIZE 16 OP_SUB OP_TOALTSTACK

// Verify preimage 2 and extract size contribution
OP_DUP OP_HASH160 <hash_2> OP_EQUALVERIFY
OP_SIZE 16 OP_SUB OP_TOALTSTACK

// ... repeat for all preimages ...

// Sum contributions from altstack
OP_FROMALTSTACK OP_FROMALTSTACK OP_ADD
// ... repeat to sum all ...

// Calculate winner index (sum mod N)
<N> OP_MOD

// Branch to winner's pubkey check
OP_DUP 0 OP_EQUAL OP_IF
    OP_DROP <pubkey_0> OP_CHECKSIG
OP_ELSE OP_DUP 1 OP_EQUAL OP_IF
    OP_DROP <pubkey_1> OP_CHECKSIG
OP_ELSE OP_DUP 2 OP_EQUAL OP_IF
    OP_DROP <pubkey_2> OP_CHECKSIG
// ... etc for all disputants ...
OP_ENDIF OP_ENDIF OP_ENDIF
```

### Timeout Fallback (Taproot Leaves)

If revelation stalls, the quorum (minus the disputed operator) can reclaim funds. Uses the same long-tail structure as reserves:

```
Leaf 1 (primary recovery):
  <timeout_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
  <threshold> <quorum_pubkeys_minus_operator> OP_CHECKMULTISIG

Leaf 2 (long tail - lower threshold, longer timeout):
  <longer_timeout> OP_CHECKSEQUENCEVERIFY OP_DROP
  <threshold-1> <quorum_pubkeys_minus_operator> OP_CHECKMULTISIG

Leaf 3 (emergency - even lower threshold, much longer timeout):
  <very_long_timeout> OP_CHECKSEQUENCEVERIFY OP_DROP
  <threshold-2> <quorum_pubkeys_minus_operator> OP_CHECKMULTISIG
```

The disputed operator is excluded from recovery paths - they lost the dispute by not maintaining custody.

## Message Changes

### DisputeArmed (modified)

```rust
pub struct DisputeArmed {
    pub reserves_id: String,
    pub operator_id: String,
    pub enforcement_height: u32,
    pub commitment_hash: [u8; 20],    // NEW: HASH160 of secret preimage
    pub target_reserves: String,       // NEW: destination for winnings
}
```

### CustodyLotteryReveal (new)

```rust
pub struct CustodyLotteryReveal {
    pub ledger_id: String,
    pub operator_id: String,
    pub preimage: Vec<u8>,  // 17 to 16+N bytes
}
```

### DisputeAcquire (modified)

```rust
pub struct DisputeAcquire {
    pub reserves_id: String,
    pub operator_id: String,
    pub claim_txid: String,           // Lottery claim tx (not confiscation tx)
    pub new_reserves_address: String,
}
```

## Transaction Flow

```
┌─────────────────┐
│ Quorum Reserves │ (Taproot, threshold sig)
│   99,999 sats   │
└────────┬────────┘
         │ Confiscation TX (quorum signs)
         ▼
┌─────────────────┐
│ Lottery Output  │ (Tapscript with hashes + pubkeys)
│   99,599 sats   │
└────────┬────────┘
         │ Claim TX (winner sig + all preimages)
         ▼
┌─────────────────┐
│ Winner Reserves │ (winner's target_reserves)
│   99,199 sats   │
└─────────────────┘
```

## Non-Revelation Handling

If a disputant doesn't reveal their preimage within the timeout:

1. **Collateral slash**: Non-revealer's collateral is forfeit to other disputants
2. **Quorum recovery**: After CSV timeout, quorum can spend lottery output back to reserves
3. **Retry**: New lottery round with remaining disputants

The collateral mechanism (already implemented) incentivizes revelation.

## Security Properties

1. **Fairness**: No party can predict or manipulate the winner
2. **Atomicity**: Either winner claims or quorum recovers (no stuck funds)
3. **Verifiability**: Anyone can verify winner calculation from preimages
4. **Trustless**: Script enforces rules, not off-chain coordination

## Implementation Checklist

- [x] Add `commitment_hash` and `target_reserves` to DisputeArmed
- [x] Create lottery Tapscript builder (LotteryScriptBuilder)
- [x] Add preimage generation/storage in `recovery arm`
- [x] Add `recovery confiscate` command (builds lottery output)
- [x] Add `recovery reveal` command (publishes preimage via Nostr)
- [x] Add `recovery lottery-claim` command (calculates winner)
- [x] Add timeout recovery scripts (CSV timelocks)
- [x] Implement quorum signature collection for confiscation TX
- [x] Build and broadcast claim transaction (lottery → winner)
- [x] Add confiscation_sign handler for quorum watcher
- [x] Update DisputeAcquire to use claim txid
- [x] Update test-dispute-4op.sh for new flow
