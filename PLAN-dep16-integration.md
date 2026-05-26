# PLAN: adopt dep-16 as the deposit-authorization model

## Why now

Mainnet is being reset. The current `verify_witness` path is a thin shim over upstream miniscript: a 200-line function in `deposits-core/src/descriptor.rs` that takes a descriptor string + a positional byte-stack witness + a message hash, parses the descriptor, lifts it to a Semantic policy, and evaluates "did some key in this policy sign this exact message?". Time/hashlocks are unsatisfiable; the only ledger-aware predicate is `after(N)` against `chain_tip - 6`.

dep-16 is in `third_party/rust-miniscript/` and has been built end-to-end with 247 tests, real-crypto ECDSA + Schnorr, canonical encodings (dep-17), witness-monotonicity (proven and tested), descriptor-rooted ast paths, internal-key rotation, fraud-proof bundles, and a `VERIFICATION.md` inventory of what's covered. It is strictly more expressive than what the protocol currently uses: typed Operations, a snapshot LedgerState the descriptor can read, keyed witnesses, and modification-as-operation.

Because we are resetting, we do not have to support both shapes. We go all dep-16.

## End state

After this lands:

- **One evaluator.** `deposits-core::evaluate(descriptor, op, ledger_state, witness) -> bool`. No fast paths, no special cases, no policy lifting. `verify_witness` and `CoreWitnessVerifier` are deleted.
- **One witness shape.** `dep16::Witness<Pk>` (keyed: sigs by key, preimages by hash, attestations by oracle key). The positional `DescriptorWitness { stack: Vec<Vec<u8>> }` is deleted.
- **One signing preimage.** The dep-17 *operation preimage* (the canonical byte encoding a witness's signatures verify against, built per-op from its type / args / nonce / expiry / deposit id) is used for every authorization-bearing operation. The five `signature_utils::*_signing_message` helpers are deleted.
- **One descriptor format.** dep-16 source / dep-17 canonical encoding. The current single-key `pk(<hex>)` becomes `wsh(prove(pk(<hex>)))` (or, where the user wants taproot semantics, `tr(<xonly>)`).
- **One modification path.** `DepositDescriptorUpdate` becomes a dep-16 `replace` at the body root, re-using the same admission, evaluation, and canonical-encoding pipeline as any other modification.
- **One fraud-proof shape.** dep-16's `FraudProof { descriptor, operation, snapshot, witness, verdict }`.
- **Witness-monotonicity is a protocol invariant.** Every admitted deposit descriptor is witness-monotone by construction; the protocol no longer has to reason about whether "holding back a signature unlocks a branch" is possible.

## Scope

Replaced (deleted in their current form):
- `deposits-protocol::types::conformance::WitnessVerifier` trait
- `deposits-protocol::types::core::DescriptorWitness`
- `deposits-protocol::signature_utils::*_signing_message` (5 helpers)
- `deposits-core::descriptor::verify_witness` and `CoreWitnessVerifier`
- The miniscript-policy-lift code path in `deposits-core/src/descriptor.rs`
- `deposits-core/Cargo.toml`'s direct `miniscript = "12"` dep (uses the calculus modules instead)

Updated (signatures change; behaviour different):
- Four call sites in `deposits-protocol/types/ledger_state.rs` move to dep-16 evaluation: `InvoiceLock`, `OnchainLock`, `TransferLock`, `DepositDescriptorUpdate`. Each evaluates the deposit's primary descriptor against a dep-16 `Operation` synthesized by the translation layer.
- `InvoiceFulfill`'s call site is **deleted** entirely (no descriptor evaluation; preimage check is the only authorization).
- A new call site for `TransferRelease` is **added**: it evaluates the `release_descriptor` that was stored at `TransferLock` time, not either deposit's primary descriptor.
- One direct call in `deposits-node/src/node/request_handlers/transfer.rs:372` updates accordingly.
- `LedgerOperation::DepositDescriptorUpdate`: carries `(sub_op, path, subtree-or-key)` matching dep-16's modification primitives.
- `LedgerOperation::TransferLock`: gains a `release_descriptor: String` arg (dep-16 source admitted at lock time, evaluated at release time).
- `LedgerOperation::DepositOpen`: the `descriptor: String` field carries dep-16 source instead of miniscript source.

Added:
- `deposits-core::dep16` (re-exports + adapters)
- `deposits-core::operations` (the `LedgerOperation → dep-16 Operation` mapping)
- `deposits-core::ledger_snapshot` (the dep-16 `LedgerState` impl deriving from protocol state)
- Per-deposit `nonce` and `expiry` fields (or their semantic equivalents) in the protocol state

Documentation:
- `DEP-01` through `DEP-15`: update every reference to "miniscript descriptor" to dep-16, and every reference to per-op signing helpers to the operation preimage
- `THIRD_PARTY.md`: subtree → submodule (already pending from the prior commit)
- New section in `book/`: "deposit authorization with dep-16" — templates, common patterns, the migration story
- `WHITEPAPER.md`: the section on deposit authorization needs the new model

## The central design table: operation mapping

### Two-layer split

The mapping is split across two layers, with distinct concerns:

| Layer | Vocabulary | What it's for |
|---|---|---|
| **Protocol** (`LedgerOperation`) | `InvoiceLock`, `InvoiceFulfill`, `OnchainLock`, `TransferLock`, `TransferRelease`, `DepositDescriptorUpdate`, … | State machine, wire format, per-op fields — stays distinct per rail |
| **Descriptor** (dep-16 `op_type`) | `spend`, `receive`, `update` | Authorization vocabulary — three symbols a descriptor's `match(operation_type(), …)` dispatches on |

A translation layer (`deposits-core::operations`) builds a dep-16 `Operation` from a protocol `LedgerOperation`, choosing the descriptor `op_type` symbol and populating args. The descriptor never sees protocol-rail distinctions directly; if it wants to discriminate by rail it dispatches on `operation_arg(kind)`.

The everyday descriptor stays a single `branch(spend, prove(pk(K)))` regardless of which rail the user spends through — this is "pk authorizes everything" → "script discerns op type" as an opt-in, same pattern as elsewhere in dep-16.

### What the descriptor sees

| Descriptor `op_type` | Built from | Args |
|---|---|---|
| `spend` | `InvoiceLock` / `OnchainLock` / `TransferLock` | `amount: int`, `kind: symbol` (`invoice` \| `onchain` \| `transfer`), `destination: bytes` or `hash`, plus rail-specific args (`payment_id`, `completion_script`, `release_descriptor`, etc., merged into the args map) |
| `receive` | `TransferRelease` into a deposit whose `receive_requires_sig=true` | `amount: int`, `source_deposit_id: hash` |
| `update` | `DepositDescriptorUpdate` | `sub_op: symbol` (`replace` \| `insert` \| `delete`), `path: path`, `subtree: subtree` (replace/insert only), `key: key` (K rotation only) |

`kind` is the only opt-in discriminator on spend. The wallet doesn't need to expose it; templates write `branch(spend, …)`; advanced users that care can write `match(operation_arg(kind), …)` inside the spend branch.

### Two carve-outs from the table

- **`InvoiceFulfill` and `OnchainFulfill` skip descriptor evaluation entirely.** The operator is at risk from the moment of lock; gating release on the deposit's descriptor would let a deposit hold the operator hostage. Preimage check (for invoice) and chain-watcher (for on-chain) are protocol-side, not descriptor-evaluated. Re-evaluating the deposit's descriptor at fulfill time is also unsound on its own: the ledger state has moved on, and the descriptor itself may have been modified between lock and fulfill.

- **`TransferRelease` evaluates a `release_descriptor` that was specified at `TransferLock` time, not either deposit's primary descriptor.** Transfer is the one rail where the operator carries no external risk between lock and release (funds stay on the operator's balance sheet), so the deposit-pair *can* gate release without holding the operator hostage. The `release_descriptor` lives in the `TransferLock` op's args, is admitted at lock time, and is evaluated against the release witness at `TransferRelease` time. For the standard intra-operator transfer it's probably `prove(hashlock(payment_id))` (HTLC) or `true` (unconditional); HTLC patterns with timeout-refund slot in naturally.

### `receive_requires_sig` stays as a bool

`DepositOpen`'s `receive_requires_sig: bool` field stays — the overwhelming default is `false` (bare `pk()` descriptors must be able to receive funds without signing each incoming credit, which is the UX-natural default). When `true`, the deposit's primary descriptor is evaluated with `op_type = receive` against the receive op. When `false`, no descriptor evaluation on receive. No new `incoming_descriptor` field; one descriptor handles both spend and receive flows, dispatching internally via `match` if the user wants different policies per direction.

## Per-deposit nonce and expiry

The operation preimage binds `nonce: u64` and `expiry: u32` as protocol-level replay protection enforced *outside* the descriptor evaluator. The protocol already has:
- A per-state-machine sequence (the operation's position in the ledger)
- Per-operation IDs (payment_id, withdrawal_id, transfer nonce)

But none of these match dep-16's "monotonically increasing per-deposit nonce". The choice:

- **(a) Add a per-deposit nonce field** to the deposit state, incremented on every authorized operation, and require operations to carry it; reject any op whose nonce is not strictly greater than the deposit's last accepted. Matches dep-16 cleanly. Adds one byte of state per deposit per op.
- **(b) Reuse an existing monotonic field as the dep-16 nonce.** The ledger sequence number works at the ledger level but not per-deposit. Per-deposit, we'd need to derive something or add a counter.

Recommend (a) — explicit, matches dep-16's semantics directly, no clever derivations to debug.

`expiry` (block height after which the signature is invalid) is straightforwardly new — every authorized op gets an expiry, and the protocol rejects ops past their expiry. The wallet sets it on submission. Default reasonable: `current_height + N` where N is something like 144 (one day on Bitcoin). User-overridable.

## LedgerState mapping

dep-16's `LedgerState` trait expects seven readings. Each one corresponds to a real protocol-side bookkeeping decision:

| dep-16 reading | Protocol-side source | Status |
|---|---|---|
| `balance()` | `deposit.balance_msats` | Exists |
| `current_height()` | Operator's chain-tip view (already plumbed into `CoreWitnessVerifier` as `chain_tip`) | Exists |
| `blocks_since_open()` | `current_height - deposit.open_height` | Need to record `open_height` per deposit |
| `blocks_since_activity()` | `current_height - deposit.last_authorized_op_height` | Need to record `last_authorized_op_height` per deposit; need to define "authorized" precisely (any op that passed verify? any op that moved value?) |
| `blocks_since_received()` | `current_height - deposit.last_incoming_payment_height` | Need to record per deposit |
| `rolling_window(field, period)` | Sum of `field` over operations in the last `period` blocks for this deposit | Need new bookkeeping; expensive if naive, can be lazy/precomputed |
| `cumulative_spent_via(path)` | Lifetime sum of spends authorized via descriptor path `path` | Need per-deposit-per-path tally; non-trivial bookkeeping |

The fields `blocks_since_*` are cheap (one height per deposit). `rolling_window` and `cumulative_spent_via` are real new state that the operator must maintain. We can phase them:
- Phase first: `balance`, `current_height`, `blocks_since_*` (cover ~80% of useful templates including social recovery, vesting cliffs, dead-man's-switch).
- Phase second: `rolling_window` and `cumulative_spent_via` (unlock rate limits, linear vesting against cumulative spend).

A `LedgerState` impl that panics on un-implemented readings catches misuse during the first phase.

## Witness shape

Today: `DescriptorWitness { stack: Vec<Vec<u8>> }` — every entry is just bytes, position-dependent.

Tomorrow: dep-16's `Witness<Pk>`:
```rust
pub struct Witness<Pk> {
    pub signatures: BTreeMap<Pk, Signature>,
    pub preimages: BTreeMap<HashValue, Vec<u8>>,
    pub attestations: BTreeSet<Pk>,
}
```

Keyed-by-key sig lookup means there is no positional consumption and no branch-selector data. The descriptor's evaluation finds witness entries by key, not by stack order. This affects:

- **Wire format.** Each operation message that today carries a `DescriptorWitness` now carries a structured witness. Serialization is whatever serde produces (or we adopt dep-17's wire format).
- **Signers.** A signer produces entries keyed by their pubkey, not stacked. Existing signers' output changes shape.
- **Tests.** Every test that builds a witness updates from `vec![vec![sig_bytes]]` to `Witness::new().with_signature(pk, sig)`.

## Phased migration

Each phase is reviewable on its own and leaves the workspace building + tests passing.

**Phase 1 — Wire up the calculus in `deposits-core`** *(small, low-risk, no behaviour change)*
- Add `deposits-core::dep16` module: re-exports the calculus types (`Descriptor`, `Witness`, `Operation`, `LedgerState`, `evaluate`).
- Add a minimal `LedgerState` adapter that wraps the protocol-side ledger state, panicking on any reading we haven't wired up yet.
- Add a unit test that evaluates a trivial dep-16 descriptor against a mock operation through the adapter.
- No call site touches yet. Cargo.toml: nothing changes.

**Phase 2 — Decide and document the operation map** *(design-heavy, code-light)*
- Write `deposits-core/src/dep16/operations.rs` that maps each `LedgerOperation` variant to a dep-16 `Operation` (op_type symbol, args, nonce, expiry, deposit_id).
- Add a `deposits-core` helper that returns the operation's sighash (the tagged hash of its operation preimage) for any `LedgerOperation` variant the descriptor evaluates against.
- Doctest each variant: show the canonical preimage bytes for a worked example.
- Still no call site touches. The new and old paths produce different message hashes — this is the protocol-incompatible change that the reset is for.

**Phase 3 — Per-deposit nonce and expiry in the protocol** *(protocol additions, narrow)*
- Add `last_op_nonce: u64` to deposit state.
- Add `nonce: u64` and `expiry: u32` to the carrying `LedgerOperation` variants (`InvoiceLock`, `OnchainLock`, `TransferLock`, `DepositDescriptorUpdate`). `InvoiceFulfill` and `OnchainFulfill` don't carry these — they're not authorized by a signature over an operation preimage.
- Add a validator rule: reject ops with `nonce <= last_op_nonce` or with `expiry < current_height`.
- Adjust wallet flow to populate both fields on signing-eligible ops.

**Phase 4 — Add the dep-16 evaluator alongside; convert `DepositDescriptorUpdate`** *(parallel paths)*
- New trait `Authorizer` in `deposits-protocol` with the dep-16-shaped signature (recommend: replace `WitnessVerifier` rather than widen it — see open questions). Add a `Dep16Authorizer` impl in `deposits-core` that owns the translation layer.
- `DepositDescriptorUpdate` is the natural first target: it's the operation most distinct from a "spend" mental model (it's modification), and its semantics map cleanly to a dep-16 `update` op carrying `(sub_op, path, subtree-or-key)`. Switch its call site to the new path.
- Verify end-to-end via a small integration test (existing `deposits-test` shapes).

**Phase 5 — Switch the spend-side call sites; add `TransferRelease`** *(the rest of the surface)*
- `InvoiceLock`, `OnchainLock`, `TransferLock` move to the dep-16 path (descriptor evaluated under `op_type=spend`).
- `TransferLock` gains a `release_descriptor: String` arg; the lock evaluation admits it.
- New `TransferRelease` op variant + call site that evaluates the lock's `release_descriptor` against the release witness.
- `InvoiceFulfill`'s descriptor evaluation is deleted; preimage check stays.
- The direct call in `deposits-node/request_handlers/transfer.rs:372` moves to the dep-16 path.
- All five `signature_utils::*_signing_message` helpers and their call sites are deleted; replaced by the operation-mapping layer producing the operation preimage uniformly.

**Phase 6 — Delete the old path** *(cleanup)*
- Remove `verify_witness`, `CoreWitnessVerifier`, `WitnessVerifier` (the old one), `DescriptorWitness`.
- Delete the policy-lifting code in `descriptor.rs`. The file may shrink to a few re-exports or be removed entirely.
- `deposits-core/Cargo.toml`: drop the direct `miniscript = "12"` line (we still depend on it through the calculus modules, but as `miniscript::calculus::*` re-exported from third_party).
- Rewrite the 13 tests in `descriptor.rs` (or move them into the calculus test suite, since they're now testing the same evaluator from the same crate).

**Phase 7 — Product documentation** *(writing-heavy)*
- Update `DEP-01..15` references to descriptors and signing messages.
- Update `WHITEPAPER.md` deposit-authorization section.
- New `book/` chapter: composing dep-16 descriptors (templates + raw).
- New CLI/wallet documentation for `expiry` and the descriptor templates.
- `THIRD_PARTY.md`: subtree → submodule update (already pending from the prior commit).

## Open design questions

Resolved during design:
- Op-type symbol naming (resolved by the two-layer split: protocol stays distinct per rail, descriptor sees `spend`/`receive`/`update` with `kind` as an opt-in spend-side discriminator).
- `DepositDescriptorUpdate` carries `(sub_op, path, subtree-or-key)` — the dep-16 modification primitives lifted into the variant.
- `receive_requires_sig` stays as a bool; primary descriptor handles `receive` evaluation when true.
- `TransferRelease` evaluates the `release_descriptor` stored at `TransferLock` time, not either deposit's primary descriptor.
- `InvoiceFulfill` and `OnchainFulfill` skip descriptor evaluation entirely.
- `Authorizer` is a new trait in `deposits-protocol` with the dep-16-shaped signature (op + state + witness + descriptor), replacing `WitnessVerifier` rather than widening it. The old trait's "default impl that accepts everything" doesn't carry over.

Still open, the points that need product input before writing more code than necessary:

1. **User's mental model for descriptors.** Three options, pick one:
   - (i) Raw dep-16 source only.
   - (ii) Template catalog → dep-16 source under the hood; raw not exposed.
   - (iii) Hybrid: templates by default, raw for power users.
   - Recommendation: (iii), starting with single-key, 2-of-3 multisig, social recovery, and Liana decaying multisig as the initial template catalogue.

2. **Capability set.** dep-16 has a minimum capability set (everything in `wsh`, plus `pk`/`pk_threshold`/`hashlock` and `older`/`after` and `spend`). What does the operator declare beyond that? Concretely: do we declare `attest` (oracle obligations) on day one if the verifier is still a stub, or wait until the attestation/oracle dep lands?

3. **Per-deposit nonce shape.** `u64` per deposit (a) monotonic-increment, or (b) free-form-but-greater-than-last? (a) is simpler; (b) lets the wallet skip ahead to avoid collisions across concurrent signers.

4. **What counts as "activity" for `blocks_since_activity`?** Any authorized operation, or only operations that moved value? Recommend: any authorized operation. Matches Bitcoin's `nSequence` analog (any signed input counts).

5. **Fraud-proof shape reconciliation.** dep-16's `FraudProof` covers descriptor + op + snapshot + witness + verdict. The protocol's current fraud machinery covers the operator's verdict on a sequence of ops. Are they compatible (we layer dep-16's bundle inside the protocol's existing replay surface) or do we adopt dep-16's shape directly? Recommend: adopt directly — the protocol's current shape was designed against the simpler `verify_witness`; dep-16's is strictly more informative.

6. **Migration story for the user (operator + holder).** Even as the only user, the wallet's saved deposits and signing-key material need to come over. The simplest version: regenerate every test descriptor from the wallet source; the wallet has been the source of truth for everything anyway. Anything special to preserve?

## Future direction

A separate deferred-design doc — [`PARTIAL_REVEAL.md`](PARTIAL_REVEAL.md) — captures the contemplation around partial-reveal, modification-replay, and leaf-Merkle commitment over a `tr` descriptor's body. None of that lands in v1; the v1 wire format (`update` carries only `(sub_op, path, replacement)`) is forward-compatible with the design space mapped there. v1 picks the simplest storage model (operator stores current materialized descriptor; full body revealed in fraud proofs) and explicitly does not foreclose any of the moves PARTIAL_REVEAL.md sketches.

## What we gain

- One evaluator across spend, modification, and policy. No more "fast path for `pk()`, general path for everything else."
- Real ledger-aware predicates: `amount_at_most_pct(p)`, `rolling_amount_below_pct(p, period)`, `destination_in(set)`. Today's protocol can't express any of these in a descriptor; they have to be hard-coded validations.
- Self-modifying deposits stop being a special case. `DepositDescriptorUpdate` is `replace [0] new_subtree`; future modification kinds (insert a new branch, delete an outdated one) come for free.
- Witness-monotonicity as a protocol invariant. The polarity check on admission means no admitted deposit has a "branch unlocked by withholding a signature" failure mode.
- Canonical encoding (dep-17). Fraud-proof replay is bit-deterministic across implementations.
- A test surface that already exists. 247 tests in `third_party/rust-miniscript`, including witness-monotonicity over 500 adversarial terms, real ECDSA + Schnorr round-trips, and the `VERIFICATION.md` inventory of what's covered.

## What we don't gain

- Real oracle integration. `attest` is a presence stub until the attestation/oracle dep lands.
- Cross-implementation conformance. We have one implementation, written collaboratively with an AI assistant; dep-17's canonical encoding is designed to support a second implementation but no second implementation exists yet.
- Performance work. The dep-16 evaluator is small but does more per op (canonical preimage construction, optional AST inspection). At single-operator scale this is not material; worth measuring once we have load.
- Backward compatibility. By design, this is a reset.
- A formal mechanized monotonicity proof. The argument in `PAPER.md §3.1` is by structural induction in prose; the 500-term randomized property test is the empirical check. A Coq/Lean mechanization would be a meaningful upgrade.

## Rough sizing

Implementation lift (engineering time, rough order):
- Phase 1: half-day. Wiring + one test.
- Phase 2: 1-2 days. Map + doctests + design discussion.
- Phase 3: 1-2 days. Protocol fields + validators + wallet.
- Phase 4: 2-3 days. Authorizer trait + Dep16Authorizer + DepositDescriptorUpdate conversion.
- Phase 5: 2-3 days. Four call sites + the direct call + wire-format flow-throughs.
- Phase 6: 1 day. Deletion + Cargo.toml + test rewrites.
- Phase 7: 2-4 days. DEP updates, whitepaper, book chapter, CLI docs.
- **Total: roughly 2 weeks of focused work**, ignoring discovery and rework.

Product description lift (separate from engineering):
- Define the operation surface (the table above is a first draft, not a finished decision).
- Define the template catalogue and the wallet's descriptor composition UI.
- Update the DEP set, whitepaper, and user-facing book for the new model.
- Decide the migration story for any existing wallet state (likely: regenerate from source).
- **This is real work, comparable in time to the engineering**, and is the bottleneck for phases 2 and 7.

## Next decision

The plan above is structured to be executed top-to-bottom. With the op-type model, the variant shape, and the `Authorizer` trait shape all decided, phase 1 is mechanical (wire up the calculus, run a trivial integration test). The substantive design work shifts to phase 2 (writing the operation-mapping translation layer in `deposits-core::operations`), where the open questions on capability set and the per-deposit nonce shape come into play.
