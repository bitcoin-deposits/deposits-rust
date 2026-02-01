# Plan: Fix Ledger Divergence Bug

## Problem Summary

The operator and partner ledgers are diverging because CollateralAttestation messages are being applied independently on each side without bilateral coordination.

### Evidence from Status Output
```
Direct: Bob → Alice  - CollateralAttestation [aeb8d883~36cc48ea]
Partner: Bob → Alice - CollateralAttestation [aeb8d883~bc032421]  ← DIFFERENT HASH!
```

Same previous hash (aeb8d883) but different resulting hashes - the messages applied are different or in different order.

## Root Cause Analysis

### Current Broken Flow (CollateralAttestation)
1. Charlie (quorum member) sends attestation to Bob (operator)
2. Bob calls `append_mut` on his ledger
3. Bob forwards attestation to Alice (partner)
4. Alice calls `append_mut` on her ledger
5. But Charlie ALSO might send directly to Alice!
6. Alice receives multiple attestations, applies them independently

**Problem**: No coordination. Each side applies their own copy at their own time, creating hash chain divergence.

### Working Pattern (LedgerAddDeposit)
1. Bob (operator) creates message
2. Bob sends to Alice and WAITS for ACK
3. Alice receives, validates, calls `append_mut`, sends ACK
4. Bob receives ACK, THEN calls `append_mut` on his own ledger
5. Both have identical message, identical previous_hash, identical result

**Key insight**: The operator must apply AFTER receiving ACK, ensuring partner applied first. Both apply the SAME message.

## Proposed Solution

### Option A: Make CollateralAttestation Coordinated (Recommended)

Change CollateralAttestation to follow the bilateral update pattern:

1. Quorum member sends attestation to **operator only**
2. Operator receives attestation and creates a "ledger update" version
3. Operator sends to partner, WAITS for ACK
4. Partner validates, applies via `append_mut`, sends ACK
5. Operator receives ACK, THEN applies via `append_mut`
6. Both have identical ledgers

**Implementation Steps**:
- Modify CollateralAttestation handler (operator side) to NOT call `append_mut` immediately
- Instead, send the attestation to partner and wait for ACK
- Only after ACK, both sides have applied
- Remove the "forward to partner" logic (replace with coordinated update)

### Option B: Remove CollateralAttestation from Ledger Hash Chain

Keep attestations as separate state, not part of the hash chain:

1. Store attestations in a separate `collateral_attestations` map
2. Don't call `append_mut` for attestations
3. Attestations inform recovery decisions but don't affect ledger hashes

**Pros**: Simpler, attestations are metadata not state
**Cons**: Less auditability, attestations not part of cryptographic record

## Affected Files

1. `src/bitcoin_deposits/handler.rs`:
   - `DepositsMessage::CollateralAttestation` handler (~line 4619)
   - Possibly `add_quorum_member` function

2. Tests:
   - `tests/ledger_sync_test.rs` - add test for CollateralAttestation sync

## Verification Plan

After fix:
1. Run `./reinit.sh` (or equivalent)
2. Check status shows identical hashes for Direct and Partner ledgers
3. Verify attestations appear in both ledgers with same hash
4. Run ledger sync tests

## Question for User

Should CollateralAttestation:
- **A)** Be a coordinated bilateral update (adds to ledger hash chain with ACK)
- **B)** Be stored separately from the hash chain (simpler but less auditable)
