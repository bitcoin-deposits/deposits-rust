# Custody Lottery: On-Chain Dispute Resolution

## Overview

When multiple operators dispute custody of a ledger, the winner must be selected fairly. This document describes an on-chain commit-reveal lottery in which the Bitcoin script itself determines the winner from entropy contributed by all disputants. No off-chain coordination on the outcome is required.

The construction supports **N = 3 to 15 disputants**, with three internal regimes that trade script structure and recovery economics. Two of the three regimes share the same dispatch strategy (linear after explicit modulo); the middle regime uses a combined dispatch table that folds the modulo into pubkey selection. The regime boundaries are chosen so that the protocol stays within reasonable witness sizes, recovery-quorum constraints, and bond economics.

## Problem

Previously, dispute resolution worked as follows:

1. Disputants arm for entropy selection
2. Wait for an entropy block
3. Off-chain calculation determines the winner from the block hash
4. Quorum members sign a custody transfer to the winner
5. Winner broadcasts `DisputeAcquire`

This approach has structural issues. The quorum must coordinate to sign for the "correct" winner, the protocol relies on off-chain agreement about who won, and the winner must collect threshold signatures. Any disagreement among the quorum about the off-chain calculation stalls or corrupts the dispute.

## Solution: Preimage Size Lottery

Each disputant commits to a secret preimage whose **byte length** contributes entropy. Because each party commits a hash before seeing others' commitments, and HASH160 is fixed at 20 bytes regardless of preimage length, no party can manipulate the outcome.

### Entropy mechanism

Each disputant:

1. Chooses a secret preimage of length 17 to 16+N bytes (where N is the number of disputants)
2. Commits `HASH160(preimage)` in their `DisputeArmed` message
3. After the confiscation tx confirms, reveals the preimage via Nostr

Winner calculation:

```
contribution_i = LEN(preimage_i) − 16        // value in {1, 2, ..., N}
total          = Σ contribution_i
winner_index   = total mod N
```

The 17-byte minimum ensures ~136 bits of preimage entropy, preventing HASH160 collision grinding to swap a preimage for one of a different length post-commitment.

### Why this is fair

The construction has the standard commit-reveal randomness-extraction property:

> **As long as at least one participant chooses their preimage length uniformly at random from {1..N}, the winner index is uniform mod N — regardless of how adversarially every other participant behaves.**

This holds because addition mod N has the one-time-pad property: adding a uniform value to anything yields a uniform result. An honest disputant does not need to trust the others; they only need to trust themselves to roll a die.

The hash commitment matters because HASH160 outputs are 20 bytes regardless of preimage length. Committing a hash leaks zero information about the chosen length, so no participant can observe another's contribution before locking in their own.

## Protocol Flow

### Phase 1: Dispute & Arm

```
Operator A: DisputeEnter { reason: "..." }
Operator B: DisputeEnter { reason: "..." }
...

Operator A: DisputeArmed {
    commitment_hash: HASH160(preimage_a),    // 20 bytes
    target_reserves: "bcrt1p...",            // winner destination
}
... (each disputant arms similarly)
```

### Phase 2: Confiscation

The quorum builds and signs a confiscation transaction:

- **Input**: current Taproot reserves (threshold signature from quorum)
- **Output**: lottery script encoding all disputants' hashes and pubkeys

The quorum does not decide the winner. It simply moves funds into a script that will compute the winner from later reveals.

### Phase 3: Reveal

After the confiscation tx confirms, disputants reveal their preimages via Nostr:

```
custody_lottery_reveal {
    ledger_id: "...",
    preimage: "deadbeef...",                  // 17 to 16+N bytes hex
}
```

All disputants should reveal. Non-revelation is handled in [Failure Modes](#failure-modes).

### Phase 4: Winner Claims

Anyone can compute the winner from the revealed preimages. The winner builds a claim transaction:

- **Input**: lottery output
- **Witness**: `<winner_sig> <preimage_n> ... <preimage_2> <preimage_1>`
- **Output**: winner's `target_reserves` address

The script verifies that each preimage hashes to the committed hash, that each preimage is of valid length, and that the computed winner index matches the signer's pubkey.

### Phase 5: DisputeAcquire

The winner publishes `DisputeAcquire` with the claim txid, completing custody transfer.

## Scaling Regimes

The construction's witness size, recovery-quorum requirement, and bond economics all change with N. We define three regimes. A single `LotteryScriptBuilder` selects the strategy automatically based on N. Regimes A and C share a dispatch strategy (linear-after-mod); they're separated because the operational characteristics — recovery frequency, bond sizing, partial-reveal handling — differ materially even though the script shape is the same.

### Summary table

| N    | Dispatch       | Mod           | Leaf size | Witness  | Min quorum | Bond ratio |
|------|----------------|---------------|-----------|----------|------------|------------|
| 3    | Linear         | Subtract      | ~300 B    | ~500 B   | T+3        | 0.67×      |
| 4    | Linear         | Subtract      | ~450 B    | ~650 B   | T+4        | 0.75×      |
| 5    | Linear         | Subtract      | ~600 B    | ~800 B   | T+5        | 0.80×      |
| 6    | Combined table | (folded in)   | ~1.5 KB   | ~1.7 KB  | T+6        | 0.83×      |
| 7    | Combined table | (folded in)   | ~2.5 KB   | ~2.8 KB  | T+7        | 0.86×      |
| 8    | Combined table | (folded in)   | ~2.7 KB   | ~3.0 KB  | T+8        | 0.88×      |
| 9    | Combined table | (folded in)   | ~3.4 KB   | ~3.7 KB  | T+9        | 0.89×      |
| 10   | Combined table | (folded in)   | ~4.3 KB   | ~4.7 KB  | T+10       | 0.90×      |
| 11   | Linear         | Subtract      | ~0.8 KB   | ~1.2 KB  | T+11       | 0.91×      |
| 12   | Linear         | Subtract      | ~0.9 KB   | ~1.3 KB  | T+12       | 0.92×      |
| 13   | Linear         | Subtract      | ~1.0 KB   | ~1.4 KB  | T+13       | 0.92×      |
| 14   | Linear         | Subtract      | ~1.1 KB   | ~1.5 KB  | T+14       | 0.93×      |
| 15   | Linear         | Subtract      | ~1.2 KB   | ~1.6 KB  | T+15       | 0.93×      |

`T` is the emergency-recovery threshold (typically the lowest threshold across the long-tail recovery leaves). `Min quorum` reflects the precondition `N_quorum − N_disputants ≥ T_emergency`.

`Bond ratio` is the lower bound on `bond / disputed_value` required to keep defection-and-eat-the-slash irrational, ignoring time value. In practice we recommend `bond ≥ 1.0 × disputed_value` for N ≥ 10.

### Regime A: N = 3–5 (linear dispatch)

Original construction, essentially unchanged. Use a linear `if/elif` cascade on the computed `sum mod N`.

```
// Stack: <sig> <preimage_n> ... <preimage_1>

// For each preimage i in 1..N:
OP_DUP OP_HASH160 <hash_i> OP_EQUALVERIFY
OP_SIZE 16 OP_SUB OP_TOALTSTACK
OP_DROP

// Sum N values from altstack
OP_FROMALTSTACK OP_FROMALTSTACK OP_ADD
OP_FROMALTSTACK OP_ADD
... (N−1 ADDs total) ...

// Compute sum mod N via repeated subtraction
// (worst case: ⌊N²/N⌋ = N subtractions)

// Linear dispatch:
OP_DUP 0 OP_EQUAL OP_IF
    OP_DROP <pubkey_0> OP_CHECKSIG
OP_ELSE OP_DUP 1 OP_EQUAL OP_IF
    OP_DROP <pubkey_1> OP_CHECKSIG
... (N arms) ...
OP_ENDIF OP_ENDIF ...
```

At this size, more elaborate dispatch structures are not worth the structural complexity. The same dispatch shape is reused in Regime C at higher N — see that section for why a tree dispatch is *not* needed even at N=15.

### Regime B: N = 6–10 (combined dispatch table)

The dispatch table grows as N(N−1)/2 + 1, so by N=6 the linear approach is wasteful. Instead, **fold the modulo into the dispatch**: emit one arm per distinct sum value, each pointing directly to the correct pubkey via the precomputed `sum mod N`.

```
// stack: sum ∈ [N, N²]
OP_DUP <N>   OP_EQUAL OP_IF OP_DROP <pubkey_0> OP_CHECKSIG    // N mod N = 0
OP_ELSE OP_DUP <N+1> OP_EQUAL OP_IF OP_DROP <pubkey_1> OP_CHECKSIG
OP_ELSE OP_DUP <N+2> OP_EQUAL OP_IF OP_DROP <pubkey_2> OP_CHECKSIG
... one arm per distinct sum value ...
OP_ENDIF × (distinct_sums − 1)
```

This is byte-for-byte competitive with separate-mod-then-dispatch through about N=10 and avoids implementing the modulo.

**Operator-facing change in this regime**: the recovery path is no longer rare. At N=10 with 95% per-party reveal probability, P(all reveal) ≈ 60%, so 40% of rounds will need recovery. Document recovery-path fees in the runbook and pre-fund a fee reserve sized for confiscation + recovery, not just confiscation + claim. Consider extending the primary CSV from 144 to 288 blocks to reduce premature recovery triggers.

### Regime C: N = 11–15 (linear-after-mod, same dispatch as Regime A)

Past N=10, the combined dispatch table grows quadratically (at N=15, 106 dispatch arms ≈ 4.8 KB). Switch back to **explicit `sum mod N` followed by linear dispatch** — the same shape as Regime A, just with more arms.

```
// Compute sum mod N via repeated subtraction.
// For N=15, sum ∈ [15, 225], up to 14 subtractions of 15.
// (Or use binary-search subtraction in ~60 bytes: subtract 15×8, then 15×4, ...)

// Linear dispatch on index ∈ [0, N−1]:
OP_DUP 0 OP_EQUAL OP_IF
    OP_DROP <pubkey_0> OP_CHECKSIG
OP_ELSE OP_DUP 1 OP_EQUAL OP_IF
    OP_DROP <pubkey_1> OP_CHECKSIG
... (N arms) ...
OP_ENDIF OP_ENDIF ...
```

#### Why not a binary tree

An earlier draft of this design specified a balanced-tree dispatch on the post-mod index, on the asymptotic argument that O(log N) tree depth beats O(N) linear chain. At this range the asymptotic argument doesn't pay off:

- **Total bytes are dominated by the N pubkey leaves**, not by the comparison ops. Both shapes spend ~38 B per arm on the pubkey + CHECKSIG, with only ~10–15 B difference in the comparison/branch structure. At N=15: linear ≈ 1.2 KB, tree ≈ 1.2 KB. The tree saves nothing material.
- **Execution cost is fine for both**. 15 sequential `EQUAL/IF` checks is well within tapscript's ops budget.
- **Tree dispatch with thresholds 8/4/2/1 has irregular bottom arms** for N ∈ {11, 13, 14, 15} — more edge cases to test and audit.
- **Sharing dispatch with Regime A halves the builder code path**. Only Regimes A and C use linear-after-mod; only Regime B is structurally different.

So Regime C is "Regime A applied at larger N." Same dispatch, different operational envelope. The regime exists as a separate label only because the operational expectations — recovery frequency, partial-reveal handling, bond sizing — differ enough to warrant their own discussion.

This regime requires the **K=1 partial-reveal leaves** described in [Failure Modes](#failure-modes), because at N=15 with 95% per-party reliability, P(all reveal) ≈ 46% — recovery is more common than completion. K=1 partial-reveal covers ~70% of those failures within CSV 72; the remainder fall through to CSV 144 quorum recovery.

## Script Construction

### Taproot structure

For N ≥ 11, the partial-reveal path is implemented as **N additional leaves**, one per possible "missing" disputant index. Each is a CSV-72-prefixed (N−1)-party lottery among the remaining disputants. This is the idiomatic Tapscript answer to polymorphic dispatch: rather than branching on a bitmap inside one leaf, encode each shape as its own leaf and let the spender pick.

```
Lottery Output (Taproot):
├── Key path: NUMS (disabled)
├── Leaf 0: Lottery claim — preimage reveal + winner sig (all N reveal)
├── Leaves 1..N (N ≥ 11 only): K=1 partial-reveal — CSV 72 prefix +
│              (N−1)-party lottery, one leaf per excluded index j ∈ [0, N)
├── Leaf N+1: Recovery — quorum minus disputants, threshold T,   CSV 144
├── Leaf N+2: Recovery — quorum minus disputants, threshold T−1, CSV 1008
└── Leaf N+3: Recovery — quorum minus disputants, threshold T−2, CSV 4032
```

Total leaf count: 4 (for N ≤ 10) or N+4 (for N ≥ 11). At N=15 that's 19 leaves — well within the practical taptree size, with Merkle path overhead of ⌈log₂ 19⌉ = 5 levels (~160 B added to the witness for the control block).

Each partial-reveal leaf is structured as:

```
72 OP_CHECKSEQUENCEVERIFY OP_DROP
<lottery script for (N−1)-party lottery excluding disputant j>
```

The (N−1)-party lottery uses the regime appropriate for N−1, **not N**. So at N=15 each partial leaf is a Regime C (linear-after-mod) lottery for 14 parties; at N=11 each partial leaf is a Regime B (combined table) lottery for 10 parties. The `LotteryScriptBuilder` handles this correctly when called with `N−1`.

Disputants are excluded from all recovery paths. They lost the dispute by failing to maintain custody (or failing to reveal), so they should not have a vote in retrieving the funds.

### Recovery leaves (long-tail structure)

Same long-tail pattern as reserves. Each leaf has a longer timeout and lower threshold than the previous, ensuring eventual recoverability under degraded operator availability.

```
Leaf k (recovery):
  <timeout_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
  <threshold> <quorum_pubkeys_minus_disputants> OP_CHECKMULTISIG
```

## Message Changes

### `DisputeArmed` (modified)

```rust
pub struct DisputeArmed {
    pub reserves_id: String,
    pub operator_id: String,
    pub enforcement_height: u32,
    pub commitment_hash: [u8; 20],     // HASH160 of secret preimage
    pub target_reserves: String,       // destination for winnings
}
```

### `CustodyLotteryReveal` (new)

```rust
pub struct CustodyLotteryReveal {
    pub ledger_id: String,
    pub operator_id: String,
    pub preimage: Vec<u8>,             // 17 to 16+N bytes
}
```

### `DisputeAcquire` (modified)

```rust
pub struct DisputeAcquire {
    pub reserves_id: String,
    pub operator_id: String,
    pub claim_txid: String,            // lottery claim tx, not confiscation
    pub new_reserves_address: String,
}
```

## Transaction Flow

```
┌─────────────────┐
│ Quorum Reserves │  Taproot, threshold sig
│   99,999 sats   │
└────────┬────────┘
         │ Confiscation TX (quorum signs)
         ▼
┌─────────────────┐
│ Lottery Output  │  Tapscript with hashes + pubkeys
│   99,599 sats   │  (regime-dependent dispatch)
└────────┬────────┘
         │ Claim TX (winner sig + all preimages)
         ▼
┌─────────────────┐
│ Winner Reserves │  winner's target_reserves
│   99,199 sats   │
└─────────────────┘
```

## Failure Modes

### Non-revelation

If a disputant does not reveal within the reveal timeout, the protocol has three escalating recovery paths:

1. **Collateral slash**: the non-revealer's bond is forfeit, distributed to other disputants. The bond ratios in the [summary table](#summary-table) keep this slash large enough that defection-by-silence is irrational.

2. **K=1 partial-reveal claim** (N ≥ 11): after CSV 72 (~12 hours), if exactly one disputant has failed to reveal, the remaining N−1 disputants can spend through the partial-reveal leaf corresponding to the missing index. This is a fair (N−1)-party lottery using the same commit-reveal mechanics. The non-revealer is simply excluded from the entropy pool and the dispatch.

3. **Quorum recovery**: after CSV 144 (~24 hours), the quorum-minus-disputants can spend the lottery output back to reserves and start a new dispute round with the remaining disputants. This is the fallback for "2+ missing" cases and for situations where no partial leaf applies.

#### Why K=1 is the partial-reveal cap

Tapscript cannot do bitmap-driven dispatch in a single leaf (no `OP_AND`, `OP_OR`, no loops), so each "shape" of the partial-reveal lottery must be its own leaf. The leaf count for K-missing partial-reveal is `C(N, K)`. K=1 adds N leaves; K=2 would add C(15,2) = 105 leaves at N=15; K=3 would add 455. K=1 covers the dominant partial-reveal case at any plausible reliability:

| p (per-party) | P(K=1 missing) | P(K≥2 missing) | K=1 covers |
|---|---|---|---|
| 0.99 | 13% | 1% | ~99% of failures |
| 0.95 | 37% | 17% | ~70% of failures |
| 0.90 | 34% | 45% | ~45% of failures |

If production reveal reliability turns out worse than ~0.95, K=2 leaves can be added later. They are a pure taptree extension — no protocol or message changes required, only construction-time leaf enumeration.

Cases not covered by K=1 (2+ disputants silent) fall through to the CSV-144 quorum recovery path, which always works as long as the recovery-quorum precondition holds. The cost is an extra ~12-hour wait.

### Reveal-reliability assumptions

P(all reveal) decays geometrically. At per-party reveal probability `p`:

| N  | p = 0.99 | p = 0.97 | p = 0.95 |
|----|----------|----------|----------|
| 3  | 97%      | 91%      | 86%      |
| 5  | 95%      | 86%      | 77%      |
| 7  | 93%      | 81%      | 70%      |
| 10 | 90%      | 74%      | 60%      |
| 15 | 86%      | 63%      | 46%      |

By N=10, recovery is a normal mode of operation. By N=15, it is the more likely outcome unless reveal reliability is exceptional. **The protocol must treat recovery as the expected path, not the exceptional one, in this regime.**

### Defection cascades

If one disputant defects per round, the round retries with N−1. To prevent an adversary controlling 2+ operators from stalling indefinitely by alternating defections across rounds, **bound the retry depth**. Recommended: at most `⌊N/2⌋` retries before declaring the dispute void and falling back to manual quorum resolution.

## Hard Limits and Preconditions

The protocol enforces these in code, not just documentation:

1. **`MAX_DISPUTANTS = 15`**. The 16th operator attempting to enter the dispute receives `DisputeFull`.
2. **Recovery-quorum precondition**: `recovery confiscate` refuses to build the lottery output unless `N_quorum − N_disputants ≥ T_emergency`. Without this check, a stalled lottery at high N is unrecoverable.
3. **Economic precondition**: if `disputed_value < 5 × estimated_claim_fee`, the lottery is not economically rational. The protocol refuses to arm.
4. **Bond precondition**: each disputant's bond satisfies `bond ≥ bond_ratio(N) × disputed_value`, with `bond_ratio` from the summary table. For N ≥ 10, bond should be at least 1.0× disputed value.

## Why N = 15 Is the Cap

Past N = 15 the construction stops being the right tool, for three independent reasons:

- **Federation size**. `N_quorum ≥ T_emergency + N_disputants` requires growing the operator set with N. Most federations cannot accommodate the recovery quorum required for N > 15 without restructuring.
- **Bond economics**. P(loss) at N=15 is 14/15 ≈ 93%. Beyond this, bonds must approach or exceed 100% of disputed value, which constrains who can participate.
- **Reveal reliability**. Recovery already dominates at N=15. Past this, the system spends most of its time in retry/recovery rather than on the happy path.

For applications requiring N > 15, switch construction: a tournament bracket of pairwise lotteries, an adaptor-signature MuSig2 scheme with constant on-chain cost, or an off-chain VRF beacon anchored on-chain. These are out of scope for this document.

## Security Properties

1. **Fairness**. As long as one disputant is honest, the winner is uniform mod N. No coalition smaller than all-of-N can bias the outcome.
2. **Atomicity**. Either the winner claims (all-reveal path), a K=1 partial-reveal leaf completes (one missing), or the recovery path returns funds to the quorum. No stuck funds, provided preconditions hold.
3. **Verifiability**. Anyone can verify the winner calculation from the revealed preimages and the on-chain script.
4. **Trustlessness**. Script enforces the rules. No off-chain agreement on outcome is required.

## Implementation Checklist

- [x] Add `commitment_hash` and `target_reserves` to `DisputeArmed`
- [x] Create `LotteryScriptBuilder` with `DispatchStrategy` enum (`Linear` | `CombinedTable`)
- [x] Auto-select strategy from N: Linear for N ≤ 5, CombinedTable for 6–10, Linear for 11–15
- [x] Add preimage generation/storage in `recovery arm`
- [x] Add `recovery confiscate` command with quorum-precondition check
- [x] Add `recovery reveal` command (publishes preimage via Nostr)
- [x] Add `recovery lottery-claim` command (calculates winner)
- [x] Add timeout recovery scripts (CSV timelocks, long-tail thresholds)
- [x] Implement quorum signature collection for confiscation TX
- [x] Build and broadcast claim transaction (lottery → winner)
- [x] Add `confiscation_sign` handler for quorum watcher
- [x] Update `DisputeAcquire` to use claim txid
- [x] Enforce `MAX_DISPUTANTS = 15` in `DisputeEnter` handler
- [x] Enforce bond ratio per regime in `DisputeArmed` handler
- [x] Enforce economic precondition (`disputed_value` vs. `claim_fee`)
- [x] Implement K=1 partial-reveal leaves for N ≥ 11 (N additional leaves at CSV 72, each an (N−1)-party lottery excluding one disputant index)
- [ ] (Future) K=2 partial-reveal leaves if production reveal reliability < 0.95
- [x] Bound retry depth to `⌊N/2⌋`
- [x] Golden test vectors at regime boundaries: N=5, N=6, N=10, N=11
- [x] Golden test vector for partial-reveal regime selection: N=11 partial leaves use Regime B (10-party); N=15 partial leaves use Regime C (14-party)
- [x] Update `test-dispute-Nop.sh` to cover N ∈ {3, 5, 6, 10, 11, 15}
- [x] Document witness sizes and recovery-fee budgets in operator runbook
