# Custody Disputes and Recovery

This document describes the custody dispute and recovery protocol for Bitcoin Deposits ledgers.

## Core Principles

1. **A ledger can never be invalid** - only specific updates can be invalid
2. **An operator:ledger combination can be non-conforming** - once judged non-conforming, that operator can never regain custody of that ledger
3. **Signature rule**: Every update must be signed by the same pubkey that signed the previous update
4. **One exception**: `CustodyDispute` can be signed by any quorum member (at the point of dispute)

## State Machine

```
NORMAL
  │
  │ CustodyDispute (from quorum member)
  ▼
DISPUTED
  │  - Quorum is disbanded
  │  - All collateral attestations voided
  │  - Only QuorumAddMember and CollateralAttestation allowed
  │
  │ CustodyArmed (pre-commitment)
  ▼
ARMED
  │  - No more quorum/collateral changes
  │  - Candidate is locked in for entropy selection
  │  - Only CustodyAcquire or CustodyYield allowed
  │
  ├─── CustodyAcquire ──► NORMAL (new operator, reserves spent)
  │
  └─── CustodyYield ───► TOMBSTONED (branch terminated)
```

## Operations

### CustodyDispute

Opens a custody dispute. Can only be signed by a quorum member (verified against the quorum at the fork point).

**Effects:**
- Disbands the quorum (all memberships voided)
- Voids all collateral attestations
- The signer becomes the "parent pubkey" for this branch
- Transitions ledger to DISPUTED state

**Fields:**
- `last_valid_sequence`: The sequence number of the last valid update before the dispute
- `reason`: Human-readable description of why the dispute was opened

### QuorumAddMember (during DISPUTED)

Adds a member to the new quorum being built. Must be signed by the dispute opener (parent pubkey).

### CollateralAttestation (during DISPUTED)

Records a collateral attestation from a quorum member. Required to prove the new custodian has backing.

### CustodyArmed

Signals that the candidate has rebuilt their quorum and is ready to compete for custody.

**Effects:**
- Locks in the current quorum - no more changes allowed
- Registers this candidate for entropy-based selection
- Only candidates with CustodyArmed before the entropy block are eligible

**Validation:**
- Must have at least N quorum members added
- Must have collateral attestations from quorum members

### CustodyAcquire

Confirms this candidate won the entropy selection and is acquiring custody.

**Effects:**
- Spends the reserves to the new custodian's address
- Transitions ledger back to NORMAL state
- This candidate is now the operator

**Validation:**
- Must be in ARMED state
- Must be the entropy-selected winner among all ARMED candidates

### CustodyYield

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
| DISPUTED | The CustodyDispute signer (parent pubkey for this branch) |
| ARMED | The CustodyDispute signer |
| After CustodyAcquire | The new operator (CustodyDispute signer) |
| After CustodyYield | No one - branch is dead |

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
        │ 18   201    bob     CustodyDispute              │
        │                     (quorum disbanded)          │
        │ 19   202    bob     QuorumAddMember(charlie)    │
        │ 20   202    bob     CollateralAttestation(charlie)
        │ 21   203    bob     CustodyArmed                │
        │          ─── entropy block 206 ───              │
        │ 22   207    bob     CustodyAcquire (winner!)    │
        └─────────────────────────────────────────────────┘

        ┌─── charlie's branch ───────────────────────────┐
        │ 18   201    charlie CustodyDispute              │
        │                     (quorum disbanded)          │
        │ 19   202    charlie QuorumAddMember(bob)        │
        │ 20   202    charlie CollateralAttestation(bob)  │
        │ 21   203    charlie CustodyArmed                │
        │          ─── entropy block 206 ───              │
        │ 22   207    charlie CustodyYield (lost)         │
        └─────────────────────────────────────────────────┘
```

## Entropy Selection

Only candidates with valid `CustodyArmed` updates before the entropy block are included in the selection.

The entropy block hash combined with candidate pubkeys determines the winner deterministically:

```
winner = candidates.sort_by(|c| hash(entropy_block_hash || c.pubkey)).first()
```

This ensures:
- No one can predict the winner before the entropy block
- Everyone can verify the winner after the entropy block
- Late entrants (CustodyArmed after entropy block) are excluded

## Validation Rules

### For a branch to be valid:

1. Each update signed by the same pubkey as the previous update
2. Exception: CustodyDispute signed by someone who was a quorum member at the fork point
3. In DISPUTED: only QuorumAddMember and CollateralAttestation allowed
4. In ARMED: only CustodyAcquire or CustodyYield allowed
5. CustodyAcquire only valid for entropy-selected winner
6. CustodyYield only valid for non-winners

### For an update to be conforming:

1. Signed by parent pubkey (or valid CustodyDispute exception)
2. Valid for the current state (NORMAL/DISPUTED/ARMED)
3. Correct sequence number (previous + 1)
4. Valid hash chain (previous_hash matches parent's current_hash)

## Notes

- A branch with CustodyYield is not "invalid" - it's simply terminated
- Multiple CustodyDispute branches can coexist - they're competing candidates
- The on-chain reserves spend happens with CustodyAcquire, not before
- Diana arriving late (CustodyDispute after others are ARMED) has no path forward - her branch will never reach CustodyAcquire
