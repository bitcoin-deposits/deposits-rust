# Chapter 14: Equivocation Defense

> **Audience**: developers, operators, integrators
> **Prereqs**: chapters 4, 11, 12
> **DEPs**: DEP-06

The protocol's deterrence story works against most operator misbehavior because the misbehavior leaves a signed trace. Skim a Lightning payment, and the preimage your wallet learned points to a confirmed payment the ledger never credited. Spend more than the reserves can cover, and `LedgerState::apply` produces a state any verifier flags as non-conforming. Backdate a cosignature, and the next update on the cosigner's own ledger contradicts the `member_ledger_hash` they swore to. In every case the cheat is captured by the operator's own signature, embedded into a chain, and made public.

Equivocation is the modality where that pattern almost breaks. An operator who signs *two different valid updates at the same sequence number* and shows them to different audiences has produced two well-formed ledger states, neither one non-conforming in isolation. No reserves overrun. No missing credit. No malformed witness. Both updates pass `checked_apply` against the same prior state. They just disagree on what the next state should be.

This chapter is about how the protocol detects that disagreement and what happens when it does. The picture is honest: equivocation defense is real but partial. The current implementation catches and converges on the common case, surfaces evidence in the uncommon case, and identifies a small set of races and a missing fraud-proof type that future work will close.

## The shape of the attack

Recall from [Chapter 4](04-ledger-state.md) that a `SignedLedgerUpdate` carries a `sequence_number`, a `previous_hash` pointing to its parent, a TLV-encoded operation, an operator signature, and a set of cosignatures. From these the chain computes:

```
content_hash = SHA256(everything-except-operator-signature)
chain_hash   = SHA256(content_hash || operator_signature)
```

`content_hash` is a stable identifier for the update's *content*. Two updates with different operations, different cosig sets, or different prior context produce different `content_hash` values.

An equivocation produces two updates `U_A` and `U_B` such that:

- Both share `sequence_number = N`.
- Both share `previous_hash = H_{N-1}` — the same parent.
- Both have valid operator signatures (the operator signed both deliberately).
- Both carry valid cosignatures from a majority of the quorum (the cosigners may have been tricked into signing both, or some subset of them was complicit).
- They differ in operation content. `content_hash(U_A) != content_hash(U_B)`.

In isolation each update is well-formed. The state machine accepts either. A wallet that sees only `U_A` builds a state where, say, deposit `D1` was credited 10,000 sats. A wallet that sees only `U_B` builds a state where the same 10,000 sats went to `D2`. No conformance check on a single chain notices anything wrong.

The attack value is real. The operator could promise different futures to different parties — assure member Alice the reserves rotation went one way and member Bob it went another, or run the inconsistency long enough to extract value from a wallet that thinks its credit is final. The Lightning preimage reveal that powers other fraud proofs doesn't help here directly, because the equivocating updates are about ledger state, not external receipts.

What stops the attack is that *the protocol assumes both updates eventually meet*. Equivocation is a denial of consistency between observers, and consistency is recovered when the observers compare notes.

## Detection in the apply path

The first line of defense is the per-ledger actor. From [Chapter 19](19-architecture-tour.md) and Chapter 20: every loaded ledger has exactly one tokio task, the `LedgerActor`, that owns the apply path. All inbound `Kind:9100` updates land in `apply_inbound` (`deposits-node/src/node/ledger_actor.rs:182`). The actor's first check after the operator-key filter is dedup on `(sequence_number, content_hash)`:

```rust
if let Some(existing) = ledger
    .history
    .iter()
    .find(|u| u.sequence_number == update.sequence_number)
{
    if existing.content_hash != update.content_hash {
        tracing::warn!(
            "LedgerActor[{}…] equivocation at seq {}: existing content {} vs new {}",
            ...
        );
    }
    return;
}
```

That branch encodes the protocol's local invariant: at any given sequence number, the actor accepts at most one update, and once an update has been applied at that slot, any later update at the same slot is rejected. If the new update has the *same* `content_hash` as the existing one, it's a relay echo — fine, no-op. If it has a *different* `content_hash`, it's equivocation evidence. The actor logs and refuses to apply it. The chain continues to extend whichever update arrived first.

This is the load-bearing observation: the operator does not get to pick which version "wins" on any given member's view. Whichever update arrives at the actor first, before the equivocating second update, is what that member commits to. The second arrival is rejected on the chain-continuity check too — by then the actor's tip has advanced, so `update.previous_hash` no longer matches `expected_prev = ledger.state.chain_tip_hash`. The dedup check is the cleaner signal, but the chain-continuity check is the backstop.

The Tier-3 test `equivocation_broadcast.rs` (`deposits-test/tests/equivocation_broadcast.rs`) exercises exactly this path. The `danger fork-update` admin command mints two valid-cosigned updates `U_A` and `U_B` at the same `(seq, prev_hash)`, broadcasts `U_A` first, sleeps four seconds, then broadcasts `U_B`. The four-second pause gives every honest member's actor time to ingest `U_A` and advance its tip, so when `U_B` arrives its `previous_hash` no longer matches anyone's chain. The test then walks each member's `<id>.jsonl` on disk and asserts:

- Each member has exactly one update at the equivocated sequence.
- That update's `content_hash` equals `U_A`'s.
- `U_B`'s `content_hash` is absent from every member's view.

In other words: one operator's deliberate equivocation, broadcast slightly staggered, produces the same chain on every honest member. The cheat doesn't slip through, the chain doesn't fork, and the operator has left forensic evidence behind in the form of `U_B` — a signed-and-cosigned update that no member's chain accepts but every member could quote back at them.

## The cross-replica invariant

The actor's local check catches equivocation when both updates reach the same actor. What about when they don't — when the operator carefully sends `U_A` to Alice, `U_B` to Bob, and never lets either arrive at the other?

This is where the cross-replica invariant comes in. Recall that members do more than apply incoming updates; they cosign outgoing ones. Every cosignature commits the cosigner to a `member_ledger_hash` — their own ledger's tip at the moment they signed. And in the symmetric direction, every cosigner maintains an internal *replica* of every ledger they're a member of, so that when the next cosign request arrives they have the prior state to validate against.

The protocol fuzzer's invariant suite codifies this in `deposits-test/tests/fuzz_protocol.rs`. After every fuzzer step, `check_all_invariants` walks every cosigner's replica of every owner's ledger and asserts:

```text
if replica.sequence == owner.sequence
    and replica.chain_tip_hash != owner.chain_tip_hash
then: possible equivocation
```

If a replica says "I cosigned a chain that ended at hash X" and the owner says "my chain ended at hash Y" and both report the same sequence, exactly one of the two is lying about what was signed at that slot — equivocation evidence. The fuzzer's canary test `equivocation_invariant_fires_on_divergent_replica` deliberately tampers a cosigner's replica state and asserts the invariant fires.

The reason this works is structural: every cosignature is a public commitment of a member to "I attest the ledger ends here, and my own ledger ends there." The operator may extract `U_A` and `U_B` from different members, but each `U_X` carries the cosigners' commitments embedded in it. Once the two updates land in the same observer's hands — which, on a public Nostr relay, is the default outcome — the equivocation is visible as a contradiction between two cosigner statements.

## Late discovery: "as of now"

The TIer-3 test's deliberately-staggered broadcast hides one subtlety: what if `U_B` shows up not four seconds after `U_A`, but four hours? Or four days? By then the chain has extended many sequence numbers past the equivocated slot. The current update is `U_{N+50}`, every step of which was honestly cosigned and applied.

The protocol's design choice is **as-of-now**: the chain does not rewind on late discovery of `U_B`. The chain that the cosigners committed to, and that downstream operations have already extended, stays the canonical chain. `U_B` becomes evidence of past misbehavior — a `SignedLedgerUpdate` carrying the operator's signature, valid in isolation, that contradicts the in-place chain's history. It is, in effect, the witness for a future `FraudProofType::Equivocation` (more on this below).

Why "as of now" and not unwind? Because unwinding the chain on late discovery would invalidate every operation that depends on the equivocated sequence — every credit, every transfer, every withdrawal that came after. Wallets and members made decisions based on the in-place chain. A wallet that received a credit at sequence N+10 is not at fault for the operator's equivocation at N, and rewriting history would put their funds in flux. The protocol prefers to honor the in-place chain and slash the operator for the out-of-place evidence.

This is the same reasoning that made the `danger fork-update` test's expectation correct: `U_B` is rejected, but neither rejected nor accepted forecloses on its later use as evidence. The signed bytes are still signed bytes. They can be carried into a fraud broadcast at any time.

## Why this isn't (yet) `FraudProofType::Equivocation`

A reader who consulted [Chapter 11](11-fraud-proofs.md) and the FraudProofType enum (`deposits-protocol/src/fraud.rs:46`) will notice equivocation is not on the list. The five types currently enumerated are `UncreditedOnchainPayment`, `UncreditedLightningPayment`, `StaleCosignature`, `DisputeDereliction`, and `NonConformingUpdate`. There is no `Equivocation` variant.

This is a deliberate state of partial coverage. The current implementation:

- **Detects** equivocation in the apply path via the actor's `(seq, content_hash)` dedup check.
- **Asserts** the cross-replica invariant in the protocol fuzzer's invariant suite, with a canary test that fires on tampered replicas.
- **Exercises** the broadcast-staggered case end-to-end in the Tier-3 `equivocation_broadcast.rs` test.

But it does not yet:

- Define a first-class `FraudProofType::Equivocation` with a canonical evidence shape (presumably `(U_A, U_B)` plus the embedding context).
- Produce that proof as a `Kind:9101` fraud broadcast that triggers the dispute pipeline like the other fraud types.
- Cover the simultaneous-broadcast race where `U_A` and `U_B` arrive interleaved at different members.

The first two are the natural next implementation step: the evidence is well-defined, the verification is straightforward (verify both signatures, verify both `previous_hash` values match, verify `content_hash` differs), and the response is the same as any other fraud proof — slash collateral, rotate custody. The third is a race-coverage gap that needs finer Nostr timing control than the broadcast test exercises.

The current state is therefore: the chain stays consistent under equivocation, but the operator who attempted it is not yet automatically slashed. The slashing path, when implemented, is mechanically identical to the other punitive paths in [Chapter 12](12-recovery-pipeline.md).

## The simultaneous-broadcast race

The pause in the Tier-3 test is load-bearing. With four seconds between `U_A` and `U_B`, every honest member's actor has time to ingest `U_A`, apply it, advance the tip, and reject `U_B` on chain-continuity grounds. If the operator instead broadcast `U_A` and `U_B` *simultaneously* — with carefully timed delivery to different members through different relay paths — different members might apply different updates first.

Consider two members Alice and Bob, both subscribed to the same set of relays but with different network latencies. The attacker times their broadcasts so Alice receives `U_A` first and Bob receives `U_B` first. Alice's actor commits to `U_A`, rejects `U_B` when it arrives later. Bob's actor commits to `U_B`, rejects `U_A` when it arrives later. The two members now disagree on the chain at sequence `N`. Neither has a singled-out chain — both have a single accepted history; it just happens to differ.

What stops this from being durable? Two things:

1. **The cross-replica invariant fires on the next cosign cycle.** As soon as Alice and Bob are both asked to cosign the operator's next update, their `member_ledger_hash` references diverge — Alice's points to a chain ending at `chain_hash(U_A)`, Bob's at `chain_hash(U_B)`. The operator cannot collect a coherent set of cosignatures from this divided quorum. The next update either fails to gather a majority or carries cosignatures across two incompatible chains, both of which are visible inconsistencies.

2. **The wallets and other observers see both versions on the relay.** Nostr broadcasts are public. Even though Alice and Bob each applied only one update, both `U_A` and `U_B` are sitting on the relay where any third party can fetch them. A wallet that subscribes to the same relay set sees both signed updates at the same sequence — direct equivocation evidence visible without any cross-quorum coordination.

The race is therefore real but bounded: it splits the quorum's view for at most one cosign cycle, and the relay-side public visibility of both `U_X` signatures makes the equivocation discoverable by anyone watching. The pending follow-up work is a Tier-3 test that drives this race deterministically (via finer Nostr timing control than the broadcast test exercises) and asserts the correct convergence behavior.

## Wallet-side defense

Wallets are the third leg of the equivocation defense. Recall from [Chapter 2](02-mental-model.md) that wallets subscribe to relays, replay updates from sequence 0, and verify the chain end to end. A wallet that subscribes to multiple relays — particularly to relays its operator is *not* the only publisher on — is an additional cross-replica observer.

If the operator equivocates, both `U_A` and `U_B` will eventually surface on a relay the wallet listens to. The wallet's replay path applies them in arrival order, and the second to arrive will fail the `(seq, content_hash)` dedup check the same way the actor's does. From the wallet's perspective this is a hard signal: the operator the wallet is depositing with has produced two contradictory signed states.

The protocol's prescribed wallet response is escalation — see [Chapter 15](15-delivery-escalation.md) for the certified-delivery embed mechanism, the standardized way wallets surface inconsistency-suspected events to the network. A wallet that has direct equivocation evidence broadcasts a delivery-embed request carrying the conflict; quorum members receive it, run their own cross-replica check, and if the evidence holds, escalate to a fraud broadcast. The economic outcome is the same as for any other fraud type: the operator loses the ledger and forfeits collateral.

This is also why wallets are encouraged to subscribe to *several* relays rather than only the one their operator advertises on. A relay operated by the same party as the ledger operator could selectively serve `U_A` to one wallet and `U_B` to another. Independent relay subscription is the only way the wallet itself becomes the cross-replica observer.

## The deterrence argument

Stripped to its skeleton, the equivocation defense story has the same shape as the rest of the protocol's deterrence:

- **The cheat is one-shot.** Once `U_A` and `U_B` both exist as signed bytes, both are durable. There is no way for the operator to retract a signed update; the relay retains it, the wallet that received it retains it, the quorum members that cosigned it retain it.
- **The detection is inevitable on a long enough timeline.** Two signed updates at the same `(seq, prev_hash)` with different `content_hash` are mathematically detectable to anyone who sees both. Public Nostr broadcast plus multi-relay wallet subscription plus quorum-member cross-replica replication makes "both are seen" the default, not the exception.
- **The economics destroy the operator.** A confirmed equivocation, once `FraudProofType::Equivocation` lands, slashes the operator's collateral the same way any other punitive proof does (Chapter 12). The reserves go to whichever member wins the custody lottery; the operator's bond is forfeit; if the operator runs other ledgers, the slashing evidence is portable across them.

The math is the same as for any other fraud type: stealing a single transfer's worth of value loses the entire collateral. With a 40/60 reserves/collateral split, a successful equivocation against, say, 100,000 sats of value-in-flight loses at least 60% of a multi-BTC reserves UTXO. There is no realistic ratio of upside to downside that makes the attempt rational.

What makes equivocation particularly unprofitable in practice is that the attack surface is small. To extract value, the operator needs to convince *some* third party — a wallet, a courier — to act on the equivocated state before the inconsistency is detected. That party then becomes the cross-replica observer who notices the conflict when they reconcile. The window in which equivocation looks profitable is the window before the second observer connects, and on a Nostr-broadcast network that window is small.

## What stays in your head

- Equivocation = two `SignedLedgerUpdate`s at the same `(sequence_number, previous_hash)` with different `content_hash`. Both validly signed, both well-formed in isolation; they only contradict each other when both are observed.
- The first line of defense is the per-ledger actor's `(seq, content_hash)` dedup. Whichever update arrives at a given member first wins; the second is rejected. The second update is durable evidence the operator equivocated, but it does not reach the chain.
- The second line of defense is the cross-replica invariant: cosigners hold replicas of the ledgers they cosign, and divergence at the same sequence between owner and replica is a fuzzer-asserted invariant violation that surfaces equivocation across observers.
- Late discovery does not rewind the chain. The protocol's design choice is "as of now": the in-place chain stays canonical, and the conflicting `U_B` becomes evidence for the future `FraudProofType::Equivocation` slashing path.
- The first-class fraud-proof variant for equivocation, the simultaneous-broadcast race test, and the wallet-side delivery-embed escalation for direct equivocation evidence are open items. The detection machinery is in place; the automated slashing response is the pending piece.

## Where this leads

[Chapter 15](15-delivery-escalation.md) opens Part IV with the certified-delivery escalation path — the protocol mechanism a wallet uses when it has evidence (equivocation, an unanswered request, a missing credit) that needs to reach the operator's quorum. Part IV's broader theme is the privacy and identity layer: how wallets find operators, how requests are routed when an operator stops responding, how identity is proved without doxxing, and how cross-ledger transfers happen via couriers.
