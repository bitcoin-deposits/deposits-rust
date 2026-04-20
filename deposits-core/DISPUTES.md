# Custody Disputes and Recovery

This document describes the custody dispute and recovery protocol for Bitcoin Deposits ledgers.

## Core Principles

1. **A ledger can never be invalid** - only specific updates can be invalid
2. **An operator:ledger combination can be non-conforming** - once judged non-conforming, that operator can never regain custody of that ledger
3. **Signature rule**: Every update must be signed by the same pubkey that signed the previous update
4. **One exception**: `DisputeEnter` can be signed by any quorum member (at the point of dispute)

## State Machine

```
NORMAL
  │
  │ DisputeEnter (from quorum member)
  ▼
DISPUTED
  │  - Quorum is disbanded
  │  - Only QuorumAddMember allowed (plus DisputeArmed to transition)
  │
  │ DisputeArmed (pre-commitment)
  ▼
ARMED
  │  - No more quorum/collateral changes
  │  - Candidate is locked in for entropy selection
  │  - Only DisputeAcquire or DisputeYield allowed
  │
  ├─── DisputeAcquire ──► NORMAL (new operator, reserves spent)
  │
  └─── DisputeYield ───► TOMBSTONED (branch terminated)
```

## Operations

### DisputeEnter

Opens a custody dispute. Can only be signed by a quorum member (verified against the quorum at the fork point).

**Effects:**
- Disbands the quorum (all memberships voided)
- The signer becomes the "parent pubkey" for this branch
- Transitions ledger to DISPUTED state

**Fields:**
- `last_valid_sequence`: The sequence number of the last valid update before the dispute
- `reason`: Human-readable description of why the dispute was opened

### QuorumAddMember (during DISPUTED)

Adds a member to the new quorum being built. Must be signed by the dispute opener (parent pubkey).

### DisputeArmed

Signals that the candidate has rebuilt their quorum and is ready to compete for custody.

**Effects:**
- Locks in the current quorum - no more changes allowed
- Registers this candidate for entropy-based selection
- Only candidates with DisputeArmed before the entropy block are eligible

**Validation:**
- Must have at least N quorum members added

### DisputeAcquire

Confirms this candidate won the entropy selection and is acquiring custody.

**Effects:**
- Spends the reserves to the new custodian's address
- Transitions ledger back to NORMAL state
- This candidate is now the operator

**Validation:**
- Must be in ARMED state
- Must be the entropy-selected winner among all ARMED candidates

### DisputeYield

Tombstones this branch - the candidate was not selected.

**Effects:**
- Terminates this branch permanently
- No further updates allowed on this branch

**Validation:**
- Must be in ARMED state
- Must NOT be the entropy-selected winner

## Signature Rules

| State | Who can sign |
|-------|--------------|
| NORMAL | Previous pubkey (the operator) |
| DISPUTED | The DisputeEnter signer (parent pubkey for this branch) |
| ARMED | The DisputeEnter signer |
| After DisputeAcquire | The new operator (DisputeEnter signer) |
| After DisputeYield | No one - branch is dead |

## Example Timeline

```
Seq  Block  Signer  Operation
───  ─────  ──────  ─────────
 0   100    alice   LedgerOpen
 1   100    alice   ReservesIncrease
 2   105    alice   QuorumAddMember(bob)
 3   105    alice   QuorumAddMember(charlie)
...
17   200    alice   OnchainCredit
        ─── alice publishes invalid update ───

        ┌─── bob's branch ───────────────────────────────┐
        │ 18   201    bob     DisputeEnter              │
        │                     (quorum disbanded)          │
        │ 19   202    bob     QuorumAddMember(charlie)    │
        │ 20   203    bob     DisputeArmed                │
        │          ─── entropy block 206 ───              │
        │ 21   207    bob     DisputeAcquire (winner!)    │
        └─────────────────────────────────────────────────┘

        ┌─── charlie's branch ───────────────────────────┐
        │ 18   201    charlie DisputeEnter              │
        │                     (quorum disbanded)          │
        │ 19   202    charlie QuorumAddMember(bob)        │
        │ 20   203    charlie DisputeArmed                │
        │          ─── entropy block 206 ───              │
        │ 21   207    charlie DisputeYield (lost)         │
        └─────────────────────────────────────────────────┘
```

## Entropy Selection

Only candidates with valid `DisputeArmed` updates before the entropy block are included in the selection.

The entropy block hash combined with candidate pubkeys determines the winner deterministically:

```
winner = candidates.sort_by(|c| hash(entropy_block_hash || c.pubkey)).first()
```

This ensures:
- No one can predict the winner before the entropy block
- Everyone can verify the winner after the entropy block
- Late entrants (DisputeArmed after entropy block) are excluded

## Validation Rules

### For a branch to be valid:

1. Each update signed by the same pubkey as the previous update
2. Exception: DisputeEnter signed by someone who was a quorum member at the fork point
3. In DISPUTED: only QuorumAddMember allowed (plus DisputeArmed to transition out)
4. In ARMED: only DisputeAcquire or DisputeYield allowed
5. DisputeAcquire only valid for entropy-selected winner
6. DisputeYield only valid for non-winners

### For an update to be conforming:

1. Signed by parent pubkey (or valid DisputeEnter exception)
2. Valid for the current state (NORMAL/DISPUTED/ARMED)
3. Correct sequence number (previous + 1)
4. Valid hash chain (previous_hash matches parent's current_hash)

## Notes

- A branch with DisputeYield is not "invalid" - it's simply terminated
- Multiple DisputeEnter branches can coexist - they're competing candidates
- The on-chain reserves spend happens with DisputeAcquire, not before
- Diana arriving late (DisputeEnter after others are ARMED) has no path forward - her branch will never reach DisputeAcquire
