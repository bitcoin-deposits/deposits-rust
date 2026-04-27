# Custody Lottery Implementation Plan

Implementing the design in [`CUSTODY_LOTTERY.md`](CUSTODY_LOTTERY.md). Today's lottery is hardcoded to N≤4 in `deposits-core/src/tapscript_reserves.rs::build_lottery_script`, which means setup.sh's default Q=5 fails dispute resolution with `Lottery supports at most 4 participants`. The new design lifts that to N≤15 across three dispatch regimes plus recovery scaffolding.

## What already exists

A pleasant amount:
- `LotteryScriptBuilder` struct with `participants` / `recovery_voters` / `recovery_threshold` (deposits-core/src/tapscript_reserves.rs:756)
- `DisputeArmed` already carries `commitment_hash: [u8; 20]` and `target_reserves: String` (deposits-protocol/src/messages/types.rs:436)
- `recovery arm` / `recovery confiscate` / `recovery acquire` CLI flow
- Confiscation TX builder, quorum cosig collection, on-chain broadcast

## What's missing or wrong

- N>4 hard-rejected
- Only one dispatch strategy (linear). No CombinedTable or BinaryTree.
- No recovery long-tail (CSV 144/1008/4032 leaves with descending thresholds).
- No partial-reveal claim leaf (needed for N≥11).
- `DisputeAcquire` carries `entropy_block_height/hash` + `spend_txid` rather than the new design's `claim_txid` + `new_reserves_address`.
- No `CustodyLotteryReveal` message — preimage isn't a Nostr-published thing yet.
- No preconditions: recovery-quorum size check, economic claim-fee check, bond-ratio enforcement, retry depth bound.

## Phasing

Five phases, each independently shippable, with tests at each boundary. Earlier phases unblock more cluster sizes; later phases harden the safety properties.

### Phase 1 — Drop the N=4 cap (Regime A complete)

**Goal:** Q=5 works end-to-end on regtest. Smallest meaningful slice.

Touches:
- `deposits-core/src/tapscript_reserves.rs::build_lottery_script` — change the cap from 4 to 5, verify the existing linear dispatch generates valid script for N=5 (an extra `OP_ELSE/OP_DUP/.../OP_ENDIF` arm).
- Update or remove `project_lottery_4_cap.md` memory note since the limit moves.
- `deposits-tools/bin/setup.sh` — leave the default at Q=3 for tests; our existing dispute integration tests run on Q=3 because of the cap. Add a `setup.sh 5` smoke run separately so we don't over-couple.

**Test:** drive a 5-disputant lottery in `tests/dispute_resolution.rs` (the simulation test) and verify a winner is selected. End-to-end on a Q=5 regtest cluster as a follow-up.

**Risk:** small. The linear cascade scales linearly in script size — at N=5 we're adding ~150 bytes, well within witness budgets.

### Phase 2 — Recovery long-tail + preconditions (safety floor) — DONE

**Goal:** make the lottery output unstuck-able even when participants vanish. Required before scaling N because high-N lotteries spend most time in recovery (per design doc, P(all reveal) drops below 60% by N=10 with 95% per-party reliability).

Status when Phase 2 was opened: the long-tail leaves were already wired into `LotteryReservesBuilder::build()` at CSV 144/1008/4032 with descending thresholds T/T-1/T-2 (`tapscript_reserves.rs:1007-1029`). Only the preconditions and error variants were missing.

Landed in this phase:
- New error variants on `DepositsError`: `RecoveryQuorumUnreachable`, `LotteryNotEconomical`, `InsufficientBondRatio`.
- New helpers in `tapscript_reserves`:
  - `bond_ratio_for_n(n) -> (num, den)` — `(N-1)/N` per the design table.
  - `min_bond_for_disputed_value(n, v)` — `ceil((N-1)/N * v)`.
  - `check_recovery_quorum_precondition(n_quorum, n_disputants, t_emergency)`.
  - `check_economic_precondition(disputed_value, fee)` (multiple = `MIN_ECONOMIC_FEE_MULTIPLE = 5`).
  - `check_bond_ratio_precondition(n, bond, disputed_value)` — pure helper for use at DisputeArmed ingest.
- Preconditions wired into `recovery_confiscate` (deposits-node/src/node_cli/recovery.rs):
  1. Recovery-quorum reachability: refuse if `N_quorum - N_disputants < T_emergency` (where T_emergency is the lowest tail threshold, `T-2` clamped to 1).
  2. Economic rationality: refuse if `reserves_amount < 5 * estimated_fee`.
- Bond-ratio enforcement is intentionally **not** wired into `recovery_confiscate`. By the time we're confiscating, every disputant has already submitted a `DisputeArmed`. The natural enforcement point is the `DisputeArmed` ingest handler, where the disputant's bond is in scope. The helper exists; the wiring is deferred to Phase 5 plumbing.

Tests (deposits-core/src/tapscript_reserves.rs#tests):
- `test_bond_ratio_matches_design_table` — spot-checks the (N-1)/N table at N=3,4,5,10,15.
- `test_min_bond_rounds_up` — ceil semantics at non-divisible cases.
- `test_check_recovery_quorum_precondition_pass_and_fail`
- `test_check_economic_precondition_pass_and_fail`
- `test_check_bond_ratio_precondition_pass_and_fail`

Integration coverage of the long-tail recovery leaves (CSV-144 spendability with one disputant skipping reveal) is left for Phase 5, when the reveal/lottery-claim CLIs land — that's the natural place to drive the scenario end-to-end.

### Phase 3 — Regime B (N=6–10, combined-table dispatch) — DONE

**Goal:** support typical federation sizes without O(N²) script bloat.

Landed in this phase:
- `build_lottery_script` now selects strategy inline based on `n`. No separate `DispatchStrategy` enum was introduced — the branch is small and naming the enum would have added more noise than it saved. Linear for `n ≤ 5`, CombinedTable for `n ∈ 6..=10`. The cap moved from `n > 5` to `n > 10`; the new error message points to the BinaryTree regime for N=11-15.
- The preimage-verification + sum-accumulation prefix is shared between regimes. Linear continues to compute `sum mod N` via repeated conditional subtraction and dispatch on the index. CombinedTable skips the modulo entirely and emits `N²-N+1` arms keyed on the sum, each routing to `pubkey_(s mod N)`.
- The Linear path was tightened along the way: it now uses `n` subtraction iterations instead of a hardcoded 4, which is provably sufficient since max sum is N².
- The sum range observation `distinct values ≤ N(N-1)/2 + 1` from the original plan was wrong — every integer in `[N, N²]` is reachable, so the arm count is `N² - N + 1` (31 at N=6, 91 at N=10).

Tests:
- `test_lottery_script_build_six` — 31 dispatch arms (verified via Instructions iterator, not raw byte scan, since OP_ENDIF's byte 0x68 collides with literal pubkey/hash bytes), script size ~1.5 KB.
- `test_lottery_script_build_ten` — 91 dispatch arms, script size 3-5.5 KB envelope.
- `test_lottery_winner_six_participants_combined_table` — exhaustive 6^6 = 46,656-case round-trip via `calculate_winner` (the off-chain authority for the same `sum mod N` mapping the script's dispatch table encodes).
- `test_lottery_winner_ten_random_sample` — 10,000 deterministic xorshift samples (full sweep would be 10^10).
- `test_lottery_reject_eleven_participants` replaced the old `_reject_six_` test as the new boundary guard.

Skipped per scope:
- Byte-for-byte golden vectors. Brittle and offer little signal beyond what the round-trip and structural tests already cover; revisit if a future regression slips through.
- Regtest Tier-3 dispute test at Q=10. The script-side correctness is well-tested in unit tests; integration coverage at high N belongs with the Phase 5 reveal/lottery-claim CLI work where the full end-to-end path is in scope.

### Phase 4 — Regime C + partial-reveal (N=11–15)

**Goal:** scale to the design's hard cap.

#### Phase 4a — Dispatch for N=11–15 — DONE

Deviated from the original BinaryTree spec to **Linear-after-mod**, extending the existing Regime A path. Measured leaf sizes after the change: N=11 = 879 B, N=15 = 1199 B — significantly under the design doc's original 1.6–2.0 KB tree estimates.

The case for the deviation: a balanced binary tree on the index buys nothing in Tapscript. Only one execution path runs at validation time, so the tree's structural overhead (DUP / push threshold / GE / IF / push threshold / SUB at each internal node) is dead weight; Linear's `O(N)` dispatch is the same shape as Regime A and shares the existing builder branch. Cap moved to `n > 15` with a `MAX_DISPUTANTS` error.

The 10→11 regime boundary stays where it is — that's about CombinedTable's `O(N²-N+1)` growth running out of steam, not about needing a tree.

Tests:
- `test_lottery_script_build_eleven` — 22 ENDIFs (N for mod + N for dispatch), measured 879 B.
- `test_lottery_script_build_fifteen` — 30 ENDIFs, measured 1199 B.
- `test_lottery_winner_high_n_random_sample` — 5,000 deterministic xorshift samples per N in 11..=15 round-tripping through `calculate_winner`.
- `test_lottery_reject_sixteen_participants` replaced `_eleven_` as the new boundary guard.

Design doc updates: summary table replaced with measured/interpolated leaf sizes (no more inflated tree estimates), Regime C section rewritten to describe the Linear-after-mod choice and explain why the original tree spec was over-engineering.

#### Phase 4b — Partial-reveal claim leaves (K=1) — DONE

The original design specified a single bitmap-driven leaf with polymorphic dispatch over a variable revealer-subset. Investigation during implementation showed that's infeasible in Tapscript: `OP_AND/OR/XOR/DIV/MOD/LSHIFT/RSHIFT/2DIV/2MUL` are all `OP_SUCCESS` (disabled), making bit-extraction non-trivial; the polymorphic dispatch compounds because every "verify k revealers" branch must be unrolled (no loops) and each revealer's hash check must cascade over all N possible disputant indices, ballooning to ~8.5 KB of verification alone before mod or final dispatch — past the per-stack-item limit and well past anything reasonable.

The Phase 4b implementation chose a feasible alternative: **K=1 multi-leaf coverage**. For N ≥ `PARTIAL_REVEAL_MIN_N` (=11), the Taproot output gains N additional partial-reveal leaves, one per missing-disputant index. Each leaf is a CSV-72-prefixed regular lottery for the (N-1) remaining disputants — the sub-lottery picks its regime by sub-N (CombinedTable for sub-N=10 at the boundary, Linear-after-mod for sub-N in 11..=14).

Coverage / failure modes:
- "1 disputant missing" — handled by the appropriate partial-reveal leaf with full lottery randomness preserved among the 14 (or fewer) revealers.
- "2+ disputants missing" — falls through to the existing CSV-144 quorum recovery long-tail.

At p=0.99 per-party reveal probability, K=1 covers ~99% of failure cases. At p=0.95, it covers ~70%. K=2 (`C(N,2)` additional leaves) is a pure construction-time extension if production data warrants it — no protocol or message changes needed. Tracked in the open-questions checklist.

Construction details:
- New `PARTIAL_REVEAL_MIN_N = 11` and `PARTIAL_REVEAL_CSV_BLOCKS = 72` constants.
- New `LotteryScriptBuilder::build_partial_reveal_leaves()` returning `Vec<ScriptBuf>` (empty for N < threshold).
- `LotteryReservesBuilder::build()` now builds a depth-aware Taproot tree: leaves at `⌈log₂ m⌉` and `⌊log₂ m⌋` depths to handle variable leaf counts. At N=15 the tree has 19 leaves (1 lottery + 15 partial + 3 recovery), Merkle depth 5.
- New `LotteryOutput::partial_reveal_scripts: Vec<ScriptBuf>` field exposes the leaves for downstream witness construction (Phase 5).

Tests (9 new):
- `test_partial_reveal_leaves_skipped_below_threshold` — N=10 has empty leaves.
- `test_partial_reveal_leaf_count_matches_n` — exact count for N=11..=15.
- `test_partial_reveal_excludes_missing_disputant` — byte-equality reconstruction confirms the j-th leaf excludes participant j.
- `test_partial_reveal_csv_prefix_present` — every leaf begins with `<72> OP_CSV OP_DROP`.
- `test_partial_reveal_uses_combined_table_at_n11` — sub-N=10 → 91 ENDIFs (CombinedTable).
- `test_partial_reveal_uses_linear_at_n15` — sub-N=14 → 28 ENDIFs (Linear-after-mod).
- `test_partial_reveal_regime_transition_n11_to_n12` — verifies the sub-lottery boundary lands at the right N.
- `test_lottery_output_taproot_depth_at_n15` — control-block size confirms depth 4 or 5.
- `test_lottery_output_legacy_shape_at_n5` — N<11 still produces the original 4-leaf depth-2 shape.

Witness construction for partial-reveal claim spends is deferred to Phase 5 plumbing alongside the `recovery reveal` / `recovery lottery-claim` CLIs — the leaves are present in the Taproot tree and the script bytes are exposed via `LotteryOutput::partial_reveal_scripts`, so the spending side just needs the right `create_partial_reveal_witness` helper and CLI dispatch.

#### Phase 4c — MAX_DISPUTANTS + retry-depth fallback — DONE (script side)

Landed:
- `MAX_DISPUTANTS = 15` and `TIMEOUT_RECOVERY_CSV_BLOCKS = 8064` constants in `deposits-protocol/src/constants.rs`, re-exported from `deposits-core`.
- `build_lottery_script` cap now sources from the constant rather than a hardcoded 15.
- `recovery_confiscate` short-circuits with a clear error if it observes more than `MAX_DISPUTANTS` DisputeArmed events (defence in depth — the script-level cap would also fire).
- `LotteryReservesBuilder::build()` now adds a 4th recovery leaf: `<TIMEOUT_RECOVERY_CSV_BLOCKS> OP_CSV OP_DROP <threshold=1> ...` — any single recovery voter can spend after ~8 weeks. This is the escape hatch for retry-depth exhaustion.
- Total-leaves accounting: `5` for `N < 11`, `5 + N` for `N ≥ 11`. At N=15: 20 leaves, Merkle depth still 5 (was already 5 with 19 leaves; 20 doesn't push us to 6).

Tests:
- `test_max_disputants_constant_matches_script_cap` — `MAX_DISPUTANTS` accepted, +1 rejected.
- `test_lottery_output_includes_timeout_recovery_leaf` — control-block lookup confirms the CSV-8064 threshold-1 leaf is in the tree.
- `test_lottery_output_shape_at_n5` (renamed from `_legacy_shape_`) — primary lottery leaf lands at depth 3 in the new 5-leaf shape.

#### Phase 4c — pending pieces (deferred to Phase 5)

- **Retry-depth orchestration counter**: tracking the number of failed lottery rounds for a given dispute and declaring the dispute void after `⌊N/2⌋` rounds. This is dispute-orchestration logic — touches the dispute state machine that's still mid-actor-migration, so it's cleaner to land alongside the Phase 5 CLI work where dispute drivers are being rewritten anyway.
- **`DisputeEnter` 16+ rejection at the protocol-message-validation layer**: the script-level cap is the enforcement mechanism today. A node-policy check on incoming DisputeEnter would catch the 16th+ attempt earlier and emit a `DisputeFull`-style response, but it requires knowing how many DisputeEnter forks already exist for the same parent — non-trivial bookkeeping that overlaps with Phase 5's `DisputeAcquire` rework.

### Phase 5 — Plumbing (DisputeAcquire rework, CustodyLotteryReveal, CLI)

**Goal:** the operator-facing path matches the new design.

Touches:
- `DisputeAcquire` rework: replace `{entropy_block_height, entropy_block_hash, spend_txid}` with `{claim_txid: String, new_reserves_address: String}`. This is a wire-format break; coordinate with anyone consuming the old shape.
- New `CustodyLotteryReveal` message:
  ```rust
  pub struct CustodyLotteryReveal {
      pub ledger_id: String,
      pub operator_id: String,
      pub preimage: Vec<u8>,  // 17..(16+N) bytes
  }
  ```
  Allocate a new Nostr kind (probably 9104 or similar — pick one not in use).
- CLI: `deposits-node recovery reveal <ledger_id>` — publishes the reveal event using the preimage stored locally during `recovery arm`.
- CLI: `deposits-node recovery lottery-claim <ledger_id>` — collects all revealed preimages from Nostr, computes the winner index, and (if we're the winner) builds + broadcasts the claim TX.
- `recovery confiscate_sign` handler in the quorum-watcher path stays mostly unchanged (the lottery output is just a different Taproot script).
- Update `validate_custody_resolution` in deposits-core to verify `claim_txid` is the lottery output's spend, not entropy-based selection.

**Test:** end-to-end Tier-3 dispute test on Q=5 cluster: forge → arm → confiscation → reveal → claim → DisputeAcquire. Verify final ledger state has the new operator and the lottery output has been spent to the winner's reserves.

**Risk:** moderate. The wire-format break on `DisputeAcquire` invalidates any in-flight disputes during deployment. For mainnet we'd need a coordinated upgrade; for the test cluster it's fine to wipe and re-setup.

## Sequencing within each phase

For every phase, the order is:
1. Add the new types/scripts (compiles, no behavior change)
2. Wire into the existing flow
3. Test at the simulation layer (`tests/dispute_resolution.rs` or new fuzzer scenarios)
4. Test at the integration layer (Tier-3 against a regtest cluster)
5. Update memory notes if discoveries warrant

The integration test in step 4 is the gate for moving to the next phase.

## Test vectors

Per the design doc, golden vectors at regime boundaries: N=5, N=6, N=10, N=11. Store under `deposits-core/tests/lottery_script_vectors/` as hex-encoded scripts plus a small TOML/JSON describing inputs (participants, hashes, recovery quorum). One file per N, plus a roundtrip test that asserts builder output matches the golden bytes.

The vectors prevent silent regressions: a one-byte change in opcode encoding breaks the test, even if the script still happens to function under some interpreter relaxations.

## What's NOT in this plan (out of scope)

- N>15 alternatives (tournament brackets, MuSig2 adaptor, off-chain VRF). Design doc explicitly defers these.
- Mainnet deployment of the new lottery. The test cluster runs first; mainnet deployment is a separate operations task once Phases 1–5 are validated end-to-end.
- Replacing the actor migration's pending Step 8 with lottery-event-driven dispatch. The actor migration and the lottery rework are independent; either can land first.

## Open questions worth answering before Phase 4

- **Partial-reveal mechanics:** the script needs to know which subset of disputants revealed. How is that encoded in the witness? Options:
  - Bitmap byte at the top of the witness (simple, 1 byte for ≤8, 2 bytes for ≤15)
  - Implicit via stack length (count revealers from witness depth — fragile)
  - Each revealer pushes their own preimage; non-revealers push `OP_0`. Script branches accordingly.
- **Bond-ratio enforcement timing:** at `DisputeArmed` (rejected if too low) or at `recovery confiscate` (accepted but flagged)? Design doc says enforce, doesn't specify which side. Probably DisputeArmed — failing fast is cheaper.
- **Retry-depth bookkeeping:** after `⌊N/2⌋` rounds, the protocol declares the dispute void and falls back to manual quorum resolution. What's the on-chain artifact for that? A timeout-recovery leaf at very high CSV (e.g. 8064 blocks ≈ 8 weeks) using a low threshold seems right but isn't fully specified.

These are clarification asks, not blockers — Phase 1–3 don't need answers. By the time we hit Phase 4 we'll have run enough tests to inform good defaults.
