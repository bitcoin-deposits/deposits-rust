# Partial reveal: a deferred design

## What this is

A capture of the contemplation around partial-reveal under tr / modification-replay, surfaced during the dep-16 integration design (see [`PLAN-dep16-integration.md`](PLAN-dep16-integration.md)). The integration ships in v1 without partial-reveal machinery; this doc names the design space so the v1 choices don't paint v2 into a corner.

Out of scope for the v1 lift.

## The tension

Three concerns pull in different directions when a deposit's descriptor is modified:

1. **Update payload minimalism.** A `DepositDescriptorUpdate` op carries only `(sub_op, path, replacement)` — not the full descriptor. Whoever applies the update has to already know the descriptor's structure to navigate the path.
2. **Verification correctness.** To validate an update, the verifier must (a) navigate the path against the current descriptor, (b) confirm the resulting candidate is admissible, (c) re-evaluate the authorization that authorized this update. All three steps require knowing the descriptor's body.
3. **Partial reveal as a property.** A `tr(K, body)` descriptor's key-path benefit — *the witness for a key-path-authorized op reveals nothing about the body* — only survives end-to-end if the operator and verifier don't have to see the body either. In v1 they do.

The first concern is satisfied by the v1 wire format. The second is what forces full reveal in v1. The third is what motivates this doc.

## Two coherent storage positions

These are about where the operator's authoritative copy of each deposit's descriptor lives. Both are fine; the choice doesn't show in the wire format.

|  | **Position A: materialized current** (v1) | **Position B: replay from history** |
|---|---|---|
| What operator stores | Current materialized descriptor per deposit | Original descriptor + ordered update list per deposit |
| Update verification | Apply patch in-place against stored current; re-admit | Append to history; re-derive current by replay; re-admit |
| Fraud proof carries | Current descriptor + disputed op + witness | Original + full update history + disputed op + witness, or snapshot of derived current with a hash chain to history |
| Partial-reveal compatible? | No — operator must see body to apply patch | Maybe — if updates carry Merkle paths through a committed body, operator can replay without ever materializing the full body |
| Storage growth | O(descriptor) per deposit | O(descriptor + history) per deposit |
| Recovery from operator state loss | Need a snapshot | Need original + full history |
| Reasoning load | Per-deposit single object | Per-deposit history; replay must be deterministic |

Position B's "replay updates to derive current" is structurally identical to dep-16's `admit_modification` iterated: the protocol already validates one update at a time and binds the deposit to the candidate; B is doing the same thing repeatedly, on demand. Same verification logic per-step, different bookkeeping around it.

v1 picks Position A. The wire format (`(sub_op, path, replacement)`) is the same under both, so the storage model can change later without breaking it.

## Three layers stackable

The partial-reveal property is a stack, not a single feature:

1. **Storage model** — Position A or B. Independent of any cryptographic commitment scheme. B is needed for #2 and #3 to compose end-to-end.
2. **Leaf-Merkle commitment over body** — a BIP-341-style Merkle tree over the body's structural slots, so a position in the body can be revealed with a Merkle path without revealing siblings. Needs admission rules that work on partially-revealed structure (the polarity check has to be expressible on a Merkle-path slice, not on full ast).
3. **Modifications as Merkle-path-revealing patches** — `(sub_op, path, replacement, merkle_path_to_position)`. Operator verifies the Merkle path, replaces the leaf, computes the new Merkle root, derives the new body commitment. The full body is never materialized.

Stack: 3 requires 2; 2 requires B; B can stand alone. dep-16's open question "leaf-Merkle commitment for `tr` script-path reveal" is layer 2. Layer 3 is the modifications counterpart.

## What v1 commits to (and what it leaves room for)

**v1 commits to:**
- Position A storage (operator keeps the materialized current descriptor per deposit).
- Update wire format `(sub_op, path, replacement)` — payload-minimal regardless of storage model.
- Full body reveal in fraud proofs (the descriptor in the proof bundle is the full text).
- No leaf-Merkle commitment scheme; descriptor commitment is the dep-17 `descriptor_id`, a hash over the full encoding.

**v1 leaves room for:**
- Position B without changing the wire format. The protocol could begin storing update history alongside materialized state at any point; new deposits transparently get a history starting from open.
- Leaf-Merkle commitment as a new scheme tag in dep-17 — e.g., `mtr` (merkle-tr) alongside `wsh` and `tr`. dep-17's scheme tag table is append-only / retire-never, so this fits cleanly.
- Layer-3 modifications under a future scheme tag, with Merkle-revealing updates encoded as a richer variant of the update op. The bare `(sub_op, path, replacement)` shape would coexist for legacy schemes.

The v1 design explicitly does not foreclose any of these. It also doesn't pre-implement any of them, because the partial-reveal property is real privacy gain but not on the critical path for a single-operator-single-user deployment.

## Open questions for whenever this is picked up

1. **Where in the scheme tag table does the Merkle variant live?** A new tag (`mtr` etc.) sits alongside `tr`; or `tr` itself sprouts a sub-variant. The first is cleaner under dep-17's append-only rule; the second changes `tr`'s decoding semantics.
2. **What's a "position" in the body for Merkle-tree purposes?** dep-16's path navigation goes through `and` / `or` / `thresh` / `not` / `if` / `match` constructors. The natural Merkle tree commits to each node's structure (head constructor + per-child hashes). Polarity check has to be expressible from a Merkle-path slice.
3. **Admission on partially-revealed structure.** The polarity check (no `prove(o)` under `not` or in an `if` condition) needs to be enforceable when the verifier sees only a path-slice of the body. One option: prove polarity at commitment time, so a Merkle path through a body whose root commits to an admitted descriptor inherits admission for the revealed slice.
4. **History bound under Position B.** Should there be a soft cap on update history length per deposit, with a snapshot/compaction step that replaces a long history with a fresh "original" at some authorized checkpoint? Unbounded history grows linearly in the deposit's lifetime.
5. **What does "compaction" look like authorization-wise?** Compaction itself is a write to a deposit; it has to be authorized. Does the deposit's current descriptor have a "compact" branch? Or does compaction live below the descriptor surface as protocol bookkeeping?
6. **Storage layout under B.** Per-deposit append-only log of updates plus a periodic materialized snapshot is a familiar pattern; the snapshot interval determines worst-case replay cost.
7. **Cross-history-version fraud proofs.** If a deposit's history is `(d_0, u_1, u_2, …, u_n)` and the disputed op is at step `k`, the fraud proof carries `d_0` + `u_1..u_k` to derive the descriptor at step `k`. Does the proof bundle compress this somehow?

## Why deferred

- The partial-reveal property is a real privacy gain. For a single-operator-single-user deployment, the operator is the user; nobody is gaining privacy from anybody. The protocol layer benefits zero from layer-3 in this configuration.
- Implementing layer 2 properly (with admission against partial structure) is genuinely intricate; the polarity proof needs to compose across slice boundaries, and the canonical encoding has to extend without breaking existing replay.
- Layer 1 alone (Position B without Merkle) is a meaningful step that could be taken at any time without coordinating with the others. It's worth the bookkeeping cost only when something downstream (compaction, snapshot scrubbing, audit trails) actually wants a derivation chain.
- v1's wire format is forward-compatible. There's no rush.

## What this doc isn't

- A commitment to ever shipping any of this. It's possible the property is best gained another way (e.g., the protocol gets multi-operator and partial-reveal moves up the priority list, and we make different choices then).
- A spec. There's no encoding here, no algorithm, no proof. It's a placeholder for future design with the boundaries marked.
- A blocker for the v1 integration. The integration plan (see [`PLAN-dep16-integration.md`](PLAN-dep16-integration.md)) proceeds under Position A with full reveal.
