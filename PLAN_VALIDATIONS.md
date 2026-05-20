# Validation consolidation

Single canonical path — `LedgerState::check_conformance` — runs at every
gate where a `LedgerOperation` is accepted onto a chain. No other path
does any essential check. Things that used to live in early-reject
preflights or per-op validators move into conformance; the early
rejects either go away or call into conformance.

## Gates that must run conformance

| Gate | Who | Today | After |
|---|---|---|---|
| Operator: building the staged update before broadcasting cosign request | `Ledger::stage_operation` | runs `validate_operation` only | runs `validate_operation` + speculative `state.clone().check_and_apply(op, verifier)` |
| Cosigner: before signing | `apply_with_verifier` inside cosign handler | already runs conformance | (unchanged) |
| Operator: applying the cosigned update | `Ledger::commit_staged_update` → `checked_apply` | already runs conformance | (unchanged) |

Speculative apply on the operator side means a clone-then-apply; we
never mutate state on a refused stage. Cost is one `LedgerState`
clone per cosign request — fine, this isn't a hot loop.

## Survivors (legitimately separate)

- **`Ledger::validate_operation`** — dispute-state allow list + `Q ≤ MAX_QUORUM_SIZE_POLICY`. Pre-state-machine policy gate; same answer from any role. Stays.
- **`Ledger::validate_for_cosign(op, current_block_height)`** — cosigner-edge: quorum-expiry refusal. Distinct from conformance because the cosigner refuses *before* applying. Stays.
- **`validate_quorum_add_member_blob`** — operator-blob shape check, no descriptor witnesses involved. Stays (rename to a private helper later if we want).
- **`validate_dispute_enter_quorum_expired`** — fraud-proof anchor evidence shape. Stays.

## Today's per-op check matrix

`apply` = `LedgerState::apply` state-machine errors.
`conf` = `LedgerState::check_conformance`.
`val` = validator in `operation_validation.rs` (paths through `validate_ledger_operation` / `handle_ledger_update`).
`hand` = daemon request handler preflight.

| Op | Check | apply | conf | val | hand |
|---|---|---|---|---|---|
| InvoiceLock | deposit exists | ✅ | | dup | |
| | available balance ≥ amount | ✅ `lock()` | | dup | |
| | amount > 0 | ❌ | ❌ | ✅ | |
| | witness valid | | ✅ | dup | dup |
| InvoiceFulfill | deposit exists | ✅ | | | |
| | witness valid | | ✅ | | |
| | preimage matches payment_id | | ✅ | dup | |
| OnchainLock | deposit exists | ✅ | | dup | |
| | available ≥ amount + fee | ✅ `lock()` | | dup | |
| | amount > 0 | ❌ | ❌ | ✅ | |
| | destination_address non-empty | ❌ | ❌ | ✅ | |
| | witness valid | | ✅ | dup | dup |
| TransferLock | source deposit exists | ✅ | | dup | |
| | available ≥ amount + fee | ✅ `InsufficientDepositBalance` | | dup | |
| | amount > 0 | ❌ | ❌ | ✅ | |
| | transfer_id == compute_transfer_id(signing_msg) | ❌ | ❌ | ✅ | dup |
| | witness valid | | ✅ | dup | dup |
| TransferComplete | pending transfer exists | ✅ | | dup | |
| | script_witness satisfies completion_script | | ✅ | dup | dup |
| DepositKeyRotate | deposit exists | ✅ | | dup | |
| | new_descriptor parseable | ❌ | ❌ | ❌ | ✅ `parse_descriptor_param` (empty only) |
| | witness valid against OLD descriptor | | ✅ | dup | dup |
| InvoiceCredit / OnchainCredit / TransferComplete | reserves ≥ obligations | ❌ | ✅ | | |
| | credit ≤ quorum collateral (if quorum active) | ❌ | ❌ | ✅ | |
| FeeCollect | fee-window elapsed | ❌ | ❌ | ✅ | |
| DepositOpen | descriptor size ≤ quorum.max_descriptor_bytes | ❌ | ❌ | ❌ | ✅ |

## Moves into `check_conformance`

These are the gaps that mean conformance today is *almost*
sufficient. Each lands as a new `ConformanceViolation` variant
emitted from `check_conformance`. None of them require new state.

1. `amount > 0` for `InvoiceLock`, `OnchainLock`, `TransferLock` →
   `ConformanceViolation::ZeroAmount { operation }`.
2. `destination_address` non-empty for `OnchainLock` →
   `ConformanceViolation::EmptyDestination`.
3. `transfer_id == compute_transfer_id(signing_msg)` for
   `TransferLock` → `ConformanceViolation::MismatchedTransferId`.
4. `new_descriptor` parseable for `DepositKeyRotate` →
   `ConformanceViolation::UnparseableDescriptor { operation }`.
   `parse_descriptor_param` in the handler keeps the empty check;
   conformance is the gate that runs `Descriptor::from_str` so
   garbage that gets past the handler still gets caught.
5. Credit ≤ quorum collateral (if quorum active) for
   `InvoiceCredit` / `OnchainCredit` / `TransferComplete` →
   `ConformanceViolation::ExceedsCollateral`.
6. Fee-window elapsed for `FeeCollect` (uses the op's own
   `block_height` field, no signature change) →
   `ConformanceViolation::FeeWindowNotElapsed`.
7. DepositOpen descriptor ≤ `quorum.max_descriptor_bytes` (when a
   quorum is active) → `ConformanceViolation::DescriptorTooLarge`.

## Operator gate: speculative conformance in `stage_operation`

```rust
pub fn stage_operation(
    &self,
    operation: LedgerOperation,
    block_height: u32,
    block_hash: [u8; 32],
    verifier: &impl WitnessVerifier,
) -> DepositsResult<StagedUpdate> {
    // ... existing role guards + validate_operation ...

    // Speculative apply + conformance. Refuses to broadcast a
    // non-conforming update to cosigners. We clone state because
    // stage_operation must not mutate self.
    let _ = self
        .state
        .clone()
        .check_and_apply(&operation, verifier)?;

    // ... existing TLV encode + SignedLedgerUpdate construction ...
}
```

Callers of `stage_operation` (currently only `LedgerActor::stage`
at `ledger_actor.rs:367`) pass `CoreWitnessVerifier::new(block_height)`.

## Deletions

After the moves and the `stage_operation` change:

1. `signing::verify_withdrawal_witness`,
   `verify_invoice_lock_witness`,
   `verify_transfer_lock_witness`,
   `verify_transfer_complete_witness` — delete. Nobody calls them
   once the in-validator witness checks are gone.
2. Witness-verification blocks inside
   `validate_deposit_key_rotate`,
   `validate_payment_lock_by_id`,
   `validate_onchain_lock_by_id`,
   `validate_transfer_lock`,
   `validate_transfer_complete` — delete. Keep the structural
   checks that haven't moved to conformance, but…
3. … those validators become redundant with `apply` + `conf` for
   everything they check. The `validate_ledger_operation`
   dispatcher (`message_validation.rs:553`) and
   `handle_ledger_update` dispatcher (`message_handlers/ledger.rs:36`)
   currently route to them. Rework both dispatchers to call
   `apply_with_verifier` instead, and delete the per-op validators.
4. Request-handler preflight `verify_witness` calls in
   `deposits-node/src/node/request_handlers/`:
   - `deposits.rs::verify_receive_witness` helper +
     its two callers.
   - `transfer.rs:85, 360, 410`.
   - `invoice.rs:458`.
   Handlers still parse the JSON witness param to fail-fast on
   shape errors, but the crypto check is conformance's job.
5. `chain_tip` parameter on the in-validator `verify_witness`
   calls — already at 0-with-TODO, those go away with the
   block deletion.

## Order of operations

Each step compiles and passes tests before the next.

1. **Add the new `ConformanceViolation` variants** to
   `deposits-protocol::types::conformance` (no behavior change
   yet — variants exist but nothing emits them).
2. **Wire the structural checks into `check_conformance`**: zero
   amount, empty destination, transfer-id match, descriptor
   parse, collateral ceiling, fee window, descriptor size.
   `cargo test -p deposits-core` catches anything that
   already exercises these via apply paths.
3. **Add `verifier: &impl WitnessVerifier` to `stage_operation`**;
   speculative `state.clone().check_and_apply`. Update the one
   caller (`LedgerActor`). Test conformance-failing stages
   are refused.
4. **Delete request-handler preflight witness checks.** Run
   the daemon's integration tests; they should still reject
   bad witnesses (now via conformance).
5. **Delete the `verify_*_witness` helpers** in `signing.rs` +
   the witness blocks in the five validators.
6. **Rework `validate_ledger_operation` and `handle_ledger_update`**
   to dispatch through `apply_with_verifier` rather than the
   per-op validators, then delete the now-unused
   `validate_*_by_id` and `validate_transfer_*` /
   `validate_deposit_key_rotate` functions.
7. **Revert** the `chain_tip` plumbing I added to
   `validate_payment_lock_by_id` in commit `fa2a68b3` — that
   path is dead after step 6.

## Out of scope (for now)

- `Older(_)` baseline in descriptor evaluation. Conformance can
  thread it later via a `relative_lock_baseline` on the verifier
  if/when we use it.
- Hash-preimage witnesses on descriptor satisfaction. Same — no
  call site needs it yet.
- BIP-322. Tracked separately.
