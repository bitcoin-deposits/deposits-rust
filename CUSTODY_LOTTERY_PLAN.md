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

### Phase 2 — Recovery long-tail + preconditions (safety floor)

**Goal:** make the lottery output unstuck-able even when participants vanish. Required before scaling N because high-N lotteries spend most time in recovery (per design doc, P(all reveal) drops below 60% by N=10 with 95% per-party reliability).

Touches:
- `tapscript_reserves.rs::build_lottery_script` — add three recovery leaves to the Taproot tree:
  - Leaf k: `<csv_blocks> OP_CSV OP_DROP <threshold> <quorum_minus_disputants> OP_CHECKMULTISIG`
  - Timeouts: 144 / 1008 / 4032 blocks
  - Thresholds: `T` / `T-1` / `T-2` (where T is the configured emergency-recovery threshold)
- `LotteryScriptBuilder::new` — accept the timeout/threshold tuples; expose `recovery_threshold_floor: u8` so callers can configure regime-specific floors.
- New precondition checks in `recovery confiscate`:
  1. `N_quorum - N_disputants >= T_emergency` — refuse to confiscate if recovery is unreachable
  2. `disputed_value >= 5 * estimated_claim_fee` — refuse if the lottery isn't economically rational
  3. Bond-ratio check from the regime table
- New error variants for these in `deposits-core::error`.

**Test:** unit tests for each precondition rejection. Integration test where one disputant skips reveal, verify the recovery leaf at CSV 144 spendable by quorum-minus-disputants.

**Risk:** moderate. The Taproot leaf set changes; the existing integration tests need to keep working. Helps to keep Phase 1's cap bump and Phase 2's leaves on separate commits.

### Phase 3 — Regime B (N=6–10, combined-table dispatch)

**Goal:** support typical federation sizes without O(N²) script bloat.

Touches:
- New `DispatchStrategy` enum in `tapscript_reserves.rs`:
  ```rust
  enum DispatchStrategy { Linear, CombinedTable, BinaryTree }
  ```
- Auto-select in `LotteryScriptBuilder::new`: `Linear` for N≤5, `CombinedTable` for 6–10, (BinaryTree placeholder for now).
- `build_combined_table_dispatch(n, sum_min..=sum_max)` — emit one `OP_DUP <s> OP_EQUAL OP_IF OP_DROP <pubkey_(s mod N)> OP_CHECKSIG` arm per distinct sum value, folding the modulo.
- The sum range is `[N, N²]`; distinct values ≤ N(N-1)/2 + 1.

**Test:** golden-vector test at N=6 and N=10. Emit the script bytes and assert byte-for-byte match. Then a regtest dispute test at Q=10.

**Risk:** moderate. Scripts get larger (~4 KB at N=10). Witness sizes need verifying against Bitcoin's policy limit (400 KB stack item / 100 KB script). All within bounds per the design doc's table.

### Phase 4 — Regime C + partial-reveal (N=11–15)

**Goal:** scale to the design's hard cap.

Touches:
- `BinaryTree` dispatch in `tapscript_reserves.rs`:
  - Compute `sum mod N` via repeated subtraction (or binary-search subtraction in ~60 bytes)
  - Tree depth `⌈log₂ N⌉ = 4` for all N in regime
  - For N not a power of 2, irregular bottom arm
- New tapscript leaf: **partial-reveal claim** for N≥11
  - Activated after a short CSV (e.g. 72 blocks) before the primary recovery
  - Treats non-revealers' contributions as 0; lottery completes among revealers only
  - Different witness shape: `<sig> <preimage_revealers> ... <revealer_count_byte>`
- `MAX_DISPUTANTS = 15` constant in deposits-protocol; `DisputeEnter` handler refuses 16+
- Retry depth bound `⌊N/2⌋` in dispute orchestration

**Test:** golden vectors at N=11 and N=15. Partial-reveal scenario test: 12 disputants, 9 reveal, lottery completes among the 9. Defection-cascade scenario: bound the retry depth, verify dispute is declared void at the cap.

**Risk:** higher. Partial-reveal logic is genuinely new; the script interaction with witness assembly is subtle. Keep the partial-reveal leaf in its own commit so it can be reverted if a witness-format issue surfaces in testing.

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
