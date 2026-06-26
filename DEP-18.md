# dep-18: consensus updates and protocol versioning

## abstract

a consensus rule change — anything that alters what a cosigner must agree is a valid ledger update: state-machine semantics, conformance checks, or the fraud-proof evaluation that replays them — cannot simply be deployed to a live fleet. if one node enforces a new rule and another does not, they diverge; worse, a node enforcing a not-yet-active rule can deem an honest peer's cosignature non-conforming and emit the confiscation-triggering fraud proof of [dep-06](DEP-06.md), seizing reserves the moment the binary rolls out. this dep specifies how new consensus rules are introduced and activated safely, building on the per-ledger version already carried by `QuorumBegin.protocol_version`. the governing invariant: **a rule is evaluated only against the version a ledger's active quorum committed to, never the validating node's newest code.**

## motivation

the protocol already versions one class of consensus rule: the on-chain reserves tapscript cascade. each ledger records an `active_ruleset_name` set from its most recent `QuorumBegin.protocol_version` (absent → `"legacy"` via `ruleset::resolve_or_legacy`), quorum members advertise the rulesets they can validate (`supported_rulesets`), and `quorum begin` refuses to rotate into a ruleset some member cannot validate (`ruleset::member_supports`). reserves reconstruction reads the ledger's own version, so a node running new code still reconstructs an old ledger under the rules that ledger was created with.

ledger-operation conformance rules (e.g. the `FeeExceedsAssessment` cap in [dep-07](DEP-07.md)) have had no equivalent gate: they were enforced unconditionally by whatever binary was running. that is unsafe for exactly the reason above. this dep extends the existing per-ledger version to cover **all** version-gated consensus rules and fixes the activation and confiscation-safety rules in one place.

## the per-ledger consensus version

every ledger has a single active consensus version:

- it is the `active_ruleset_name` on `LedgerState`, set by the ledger's most recent `QuorumBegin.protocol_version`;
- a missing field (pre-versioning `QuorumBegin`s) resolves to `"legacy"`;
- it bundles **all** version-gated consensus rules for that ledger — the reserves tapscript cascade *and* ledger-op conformance rules. one knob per ledger, not one per rule.

each named version has a monotonic **epoch** (a `u16`) assigned in the registry. epochs are totally ordered so rules can declare "active from epoch N onward." `legacy` is epoch 0. a node knows a finite, append-only set of versions (`ruleset::all_supported_names`, each with its epoch); it never invents one.

a rule is **active for a ledger** iff `epoch(ledger.active_ruleset_name) >= epoch_introducing(rule)`. rules with no introducing epoch (rules that predate versioning, such as reserve-backing and the `FeeWindowNotElapsed` timing check) are active under every version, including `legacy`.

## lifecycle of a consensus change

1. **specify.** the rule lands in a dep and is assigned to a named version with a fixed epoch.
2. **implement, dormant.** the code enforces the rule only when the ledger's active epoch is at or past the introducing epoch. under any older version the code path is byte-for-byte identical to pre-change behaviour. *shipping the binary changes nothing observable on existing ledgers.*
3. **advertise.** quorum members that can validate the new rule publish the new version name in their signed `supported_rulesets` (`QuorumMemberResponse`; surfaced in the operator's kind 39100). a member that cannot validate it simply does not advertise it.
4. **activate, per-ledger.** at the next quorum rotation the operator issues a `QuorumBegin` naming the new version. `quorum begin` refuses that version unless **every** member supports it (`member_supports`), so a quorum can never commit to rules one of its own cosigners cannot check. from that `QuorumBegin`'s sequence forward, the rule is active for that ledger.
5. **no flag-day.** ledgers that have not rotated keep their prior version and prior rules until they themselves rotate. the fleet upgrades ledger by ledger, at each ledger's own rotation cadence.

## confiscation-safety invariant (normative)

this is the property that makes deploying ahead of activation safe.

- conformance evaluation and **all** fraud-proof replay MUST be performed against the version the ledger's active quorum committed to at the relevant sequence — read from `active_ruleset_name` in the replayed state — and MUST NOT use the validating node's newest ruleset.
- a node MUST NOT emit, accept, relay, or act upon a `NonConformingCosignature` (or any other confiscation-triggering fraud proof, per [dep-06](DEP-06.md)) whose only basis is a rule not active under the governing version of the cosigned operation.
- a cosignature is fraudulent only if it blesses an operation that is non-conforming **under the rules in force for that ledger at that sequence**. a rule introduced at epoch N can never make an operation cosigned under epoch < N retroactively fraudulent.

corollary: deploying a binary that knows version N is always safe regardless of which ledgers have rotated. it cannot retroactively fault pre-rotation history, and it cannot fault peers still running the older binary on not-yet-rotated ledgers.

## version negotiation and refusal

- **per-ledger (consensus).** the operator selects, at `QuorumBegin`, the highest version that every member's `supported_rulesets` covers. a pending member that cannot validate the target version blocks rotation into it — `member_supports` returning false is a hard stop, not a warning, because a quorum that cannot uniformly validate its own rules cannot safely cosign.
- **per-peer (transport).** the wire handshake's `protocol_version` / `min_protocol_version` (`messages::constants`) governs whether two nodes will talk at all. this is independent of the per-ledger consensus version: a node may speak the latest wire protocol while operating ledgers pinned to `legacy` consensus rules.

## downgrade, stall, and emergency paths

- there is no forced upgrade. an operator whose members cannot all support a new version simply keeps its current version and forgoes the new rule; the ledger remains fully operable.
- a `QuorumBegin` may re-select the current version (the common case for a routine membership rotation) or, in principle, an earlier one that all members still support. rule activation is monotonic per *change* but the version field itself is whatever the rotation commits.
- self-rescue and dispute resolution ([dep-06](DEP-06.md)) evaluate each disputed operation against the version active at that operation's sequence. an upgrade in flight never changes the rules applied to operations already committed under the prior version.

## worked example: the dep-07 fee-assessment cap

the maintenance-fee one-period cap from [dep-07](DEP-07.md) splits cleanly across this boundary:

- the **operator-side** cap in `calculate_fees_due` (`assessed_blocks = min(blocks_elapsed, frequency_blocks)`) is safe to deploy immediately and unconditionally. it only ever makes the operator collect *less*, which is conforming under every version, including `legacy`.
- the **consensus rule** `FeeExceedsAssessment` — cosigners rejecting a `FeeCollect` whose `amount` exceeds the one-period assessment — is version-gated. it is introduced at version **`fee-cap-v3`** (the next registry epoch after `cltv-offset-v2`). until a ledger's `QuorumBegin` names `fee-cap-v3`:
  - cosigners do **not** enforce the amount cap (they still enforce the pre-versioning `FeeWindowNotElapsed` timing check), and
  - an over-cap `FeeCollect` is **not** a confiscation basis.
- after a ledger rotates to `fee-cap-v3`, the cap is a hard conformance rule and an over-cap `FeeCollect`, if cosigned, is a valid `NonConformingCosignature` for that ledger.

the genesis-baseline stamping for `last_fee_assessment` (dep-07) is likewise version-gated where it changes a conformance input (the timing check's `next_allowed_block` and the fee-change window); it ships dormant and activates with `fee-cap-v3`.

## related deps

- [dep-05](DEP-05.md): quorum formation and rotation; member `supported_rulesets` and join-time minimums.
- [dep-06](DEP-06.md): disputes, fraud proofs, and confiscation — the cascade this dep keeps from misfiring during an upgrade.
- [dep-07](DEP-07.md): the fee-assessment cap, the first ledger-op conformance rule to use this process.
- [dep-16](DEP-16.md) / [dep-17](DEP-17.md): descriptor evaluation and the canonical encodings whose bit-for-bit determinism the per-version fraud-proof replay depends on.
