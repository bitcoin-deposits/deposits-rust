# Chapter 12: Recovery Pipeline

> **Audience**: operators, developers, advanced wallet users
> **Prereqs**: chapters 4, 7, 11
> **DEPs**: DEP-06

## Why this chapter exists

[Chapter 11](11-fraud-proofs.md) ends at the moment a fraud proof is broadcast. The proof is causally embedded in some ledger; the `Kind:9101` event is on the relay; quorum members of the accused ledger see it. What happens next is the subject of this chapter: how the proof gets converted into custody change, how the operator's collateral is forfeited, and how the ledger's deposits keep functioning through the transition.

The pipeline has six stages plus a cleanup phase. If you internalize the names in order — *detect, fork, enter, arm, lottery, acquire, cleanup* — the rest of the chapter is filling in what happens at each one.

The recovery pipeline is the protocol's slashing engine. It is what makes the network's central trust assumption — at least one honest quorum member per ledger — load-bearing. Everything else (fee schedules, reserves accounting, conformance checks at cosign time) reduces to "if this gets violated, the recovery pipeline takes the operator's collateral." Without the pipeline, there is nothing behind the conformance rules but social pressure.

## The pipeline at a glance

A picture first, with the actors:

```
  Operator: Alice           Quorum: Bob, Carol           Wallet
  ─────────────────         ──────────────────           ──────
       │                          │                        │
       │ produces non-conforming update                    │
       │ (e.g. uncredited LN payment)                      │
       │                          │                        │
       │                          │  fraud proof (Kind 9101)
       │                          │ <──────────────────────│
       │                          │                        │
       │                  Stage 1: DETECT                  │
       │                          │                        │
       │             Stage 2: FORK (each member            │
       │             forks from last conforming seq)       │
       │                          │                        │
       │             Stage 3: ENTER (DisputeEnter on fork) │
       │                          │                        │
       │             Stage 4: ARM (DisputeArmed on fork    │
       │             with HASH160(preimage_i))             │
       │                          │                        │
       │             Stage 5: LOTTERY                      │
       │             ┌─ confiscation TX (recovery quorum)  │
       │             ├─ reveals (Kind 9106)                │
       │             └─ claim TX (winner only)             │
       │                          │                        │
       │             Stage 6: ACQUIRE (DisputeAcquire on   │
       │             winner's fork → ledger now Bob's)     │
       │                          │                        │
       │                          │  ledger advert refresh │
       │                          │ ──────────────────────>│
       │                          │                        │
       │                          │  wallet routes future  │
       │                          │  requests to new       │
       │                          │  operator's pubkey
```

Three things to notice. The accused operator (Alice) does not appear in stages 2–6 — the operator cannot dispute their own ledger, so Alice is excluded from the disputant set. Disputants are exactly the (Q-1) other members. Each runs the pipeline on a *fork* of the ledger they agree was canonical up to the divergence point; the on-chain lottery selects one as the new operator and only the winner's fork survives.

Alice's main ledger keeps existing as a chain on the relay, but it is now orphaned. Wallets stop trusting updates signed by Alice's pubkey on that ledger ID; they accept updates signed by the new operator's pubkey on the same ID. Same `ledger_id`, new `parent_pubkey` — the ledger's identity persists across the custody transfer.

Stages happen on the relay (cosigned updates as `Kind:9100`, fraud proofs as `Kind:9101`, dispute events as `Kind:9103`, reveals as `Kind:9106`) and on Bitcoin (the confiscation TX and the lottery claim TX). The relay events carry cause, evidence, and coordination; the Bitcoin script is the arbiter of who gets the money.

## Stage 1: Detection

A fraud proof becomes actionable when a quorum member of the accused ledger observes the corresponding `Kind:9101` event. In the implementation, this is the inbound dispatcher in `deposits-node/src/node/inbound.rs` recognizing the kind and routing to the proof verifier. Verification is local and deterministic: the verifier replays evidence against the cited updates, checks signatures, and either accepts or rejects.

A member who accepts the proof has two responsibilities: escalate by initiating the fork-and-enter sequence, and stop cosigning further updates from the operator on the original chain. Cosigning post-detection is itself slashable evidence (`StaleCosignature` against the member, see Chapter 11), so the protocol gives members a strong reason to act fast.

Members can also detect non-conformance directly, without an external `Kind:9101` broadcast. The reference implementation's `recovery start` subcommand walks the ledger and produces a `Kind:9103` dispute event when it finds a violation locally. Both paths converge at the next stage.

## Stage 2: Fork

The disputant creates a new chain rooted at the last conforming update. Subsequent operations land on the *fork branch*, not on the original chain. The fork has the same `ledger_id` as the original (the ledger is the conceptual entity that will get a new operator) but is stored separately on disk and tracked by a *fork key*.

In `deposits-node/src/node/dispute.rs::auto_arm_for_dispute`:

```
fork_key = self.create_dispute_fork(ledger_id, last_valid_seq)?;
```

Each disputant produces their own fork key, deterministic from the ledger ID and disputant pubkey. The fork ledger is a fresh `Arc<RwLock<Ledger>>` initialized with history copied from the original up to `last_valid_seq`, plus `parent_pubkey` rotated to the disputant's key. Quorum members are copied across so the fork can keep cosigning under the same membership.

Forks are isolated from the original and from each other. Bob's fork and Carol's fork are independent in-memory structures; they only couple at the on-chain lottery. The `last_valid_seq` is the last sequence at which the chain conformed: for a `StaleCosignature` proof against sequence 47, `last_valid_seq = 46`. Anything ≥ 47 on the original is presumed non-conforming and is not carried into the fork.

## Stage 3: DisputeEnter

The first operation appended to the fork is a `DisputeEnter`. Its wire form is two fields:

```rust
DisputeEnter {
    last_valid_sequence: u64,
    reason: String,
}
```

`reason` is informational ("auto_dispute", "uncredited LN payment for hash 0xabcd..."). The protocol does not parse it; a reader walking the chain sees why the dispute was opened.

`DisputeEnter` is the one operation that can change the operator-key on a ledger without prior cosigning consent. Normally an update must be signed by the same pubkey as the previous update; `DisputeEnter` is the explicit exception (see `deposits-protocol/src/messages/types.rs:411-416`). Signed by any pubkey that was a quorum member at the fork point, it transitions the fork's `DisputeState` from `Normal` to `Disputed` and rotates the fork's `parent_pubkey` to the disputant.

There is one `DisputeEnter` per disputant per fork — each disputant has their own fork, each fork carries its own `DisputeEnter` as the first divergent operation.

The operator's main chain is *not* affected by the fork's `DisputeEnter`. `DisputeState` is per-ledger-instance; the operator's main chain stays in `Normal` because no `DisputeEnter` ever lands on it. The integration test `dispute_initiation.rs` calls this out explicitly:

> tier 1 deliberately does NOT check op0's main-ledger `dispute_state`. The protocol model is that a fork branch carries the dispute; the operator's main chain only flips state on a confirmed `DisputeAcquire` (custody transfer) or `DisputeYield`.

This separation is what lets the operator keep running their other ledgers while one is disputed. Multi-ledger slashing comes from a different mechanism — see below.

## Stage 4: DisputeArmed

After `DisputeEnter`, the disputant appends `DisputeArmed`:

```rust
DisputeArmed {
    armed_block: u32,
    commitment_hash: [u8; 20],   // HASH160 of secret preimage
    target_reserves: String,     // bcrt1p...  bitcoin address
}
```

This is the disputant's commitment to the on-chain lottery. Three fields:

- **`armed_block`**: the block height at which the disputant armed. Used as the timing reference; late entries (after `dispute_arm_blocks` from the first `DisputeEnter`) are excluded.
- **`commitment_hash`**: HASH160 of the disputant's secret preimage. The preimage is 17 to (16+N) bytes long; the *length* contributes the entropy. ([Chapter 13](13-custody-lottery.md) covers why.)
- **`target_reserves`**: the bitcoin address for the winnings if this disputant wins.

`DisputeArmed` advances the fork's `DisputeState` from `Disputed` to `Armed`. From here only `DisputeAcquire` (winner) or `DisputeYield` (loser) is valid.

Each disputant arms independently. The lottery fires once *all* expected disputants have armed (or the arm window closes). Expected disputants = quorum members minus operator. For Q=3 with Alice operator, that's {Bob, Carol}.

`auto_arm_for_dispute` in `dispute.rs` handles `DisputeEnter` and `DisputeArmed` together: by the time a disputant has finished forking and entering, they arm with a freshly-generated 32-byte preimage. Stages 3 and 4 are usually sub-second after detection.

## Stage 5: Lottery

The lottery is the on-chain phase. It has three substages — confiscation, reveal, claim — and is where Bitcoin script (not the relay) becomes authoritative. [Chapter 13](13-custody-lottery.md) is the full treatment; here we just walk the surface.

**Confiscation**: the *recovery quorum* (quorum members minus disputants) cosigns a Bitcoin transaction that spends the operator's reserves UTXO into a fresh Taproot output, the *lottery output*. Its tapscript tree contains a primary lottery-claim leaf parametrized by every disputant's `commitment_hash` and `target_reserves`, plus partial-reveal and fallback-recovery leaves. Once the confiscation TX confirms, the reserves are reachable only via whichever path the lottery selects.

`auto_confiscate` (`dispute.rs:889`) runs this in two phases: *initiate* (build the confiscation TX, request cosignatures, broadcast at threshold) and *collect* (gather cosignature responses, retry stale requests). On confirmation each participating member writes a `confiscated_<prefix>.marker` — that's what `dispute_initiation.rs` polls for as proof the pipeline ran end-to-end.

The recovery quorum requirement is a hard precondition: `N_quorum − N_disputants ≥ T_emergency`. If too many members are disputants, there is no signing quorum for the confiscation TX. This is one reason the script's CSV-gated recovery cascade exists — even at large N, there must be a path back to the funds.

**Reveal**: each disputant publishes a `Kind:9106` `CustodyLotteryReveal` carrying their preimage. Anyone can verify `HASH160(preimage) == commitment_hash` from `DisputeArmed` and compute:

```
contribution_i = LEN(preimage_i) − 16     // ∈ {1..N}
sum            = Σ contribution_i
winner_index   = sum mod N
```

The `winner_index`-th disputant (by sorted pubkey) is the winner.

**Claim**: only the winner's signature satisfies the lottery-claim leaf, because the script computes `winner_index` from the supplied preimages and demands the signature match the corresponding pubkey. The winner broadcasts a *claim TX* spending the lottery output to their `target_reserves`. The confirmed claim TX is the on-chain proof of who took custody — Bitcoin consensus, not relay events.

If a disputant fails to reveal, the lottery falls through to a partial-reveal leaf (one missing) or a CSV-gated recovery cascade (multiple missing). Chapter 13 covers these.

## Stage 6: DisputeAcquire

Once the claim TX is confirmed, the winner appends `DisputeAcquire` to *their* fork:

```rust
DisputeAcquire {
    new_custodian: PublicKey,
    claim_txid: [u8; 32],
    new_reserves_address: String,
}
```

This is the operator-key rotation made explicit on the chain. The fork's `DisputeState` returns to `Normal`, `parent_pubkey` becomes the winner's pubkey, the reserves are at the new on-chain address. The fork is now the canonical continuation of the ledger.

`DisputeAcquire` is meaningful only because the claim TX is on-chain verifiable. A disputant who publishes `DisputeAcquire` without the corresponding confirmed claim TX is asserting something the script disagrees with, and wallets must wait:

> Wallets must not accept post-dispute updates until the on-chain claim transaction is confirmed. The claim transaction's witness satisfies the lottery script's `(sum mod N)`-th-disputant rule, so Bitcoin itself proves the new custodian is the script-selected winner. — DEP-06 §Recovery

Losing disputants append `DisputeYield` instead — a no-fields operation that transitions the fork's `DisputeState` to `Tombstoned`, after which no further operations on that fork are valid.

`auto_lottery_claim_or_yield` (`dispute.rs:364`) handles both cases. It scans the relay for revealed preimages, computes the winner index, and either constructs the claim TX + `DisputeAcquire` (if it's us) or emits `DisputeYield` (if it's not).

## DisputeState transitions

The ledger-level state machine is small. From `deposits-protocol/src/types/core.rs:683`:

```
   ┌─────────┐  DisputeEnter   ┌──────────┐  DisputeArmed   ┌───────┐
   │ Normal  │ ──────────────> │ Disputed │ ──────────────> │ Armed │
   └─────────┘                 └──────────┘                 └───────┘
        ▲                                                       │
        │                                            DisputeAcquire│DisputeYield
        │                                                       ▼
        │                                                  ┌────────────┐
        └──────────── DisputeAcquire ──────────────────────│            │
                                                           │ Tombstoned │
                                                           └────────────┘
                                                          (on yield only)
```

`Normal` allows all operations except the Dispute family except `DisputeEnter`. `Disputed` allows only `QuorumAddMember` and `DisputeArmed`. `Armed` allows only `DisputeAcquire` or `DisputeYield`. `Tombstoned` allows nothing.

`Normal` is reachable from `Armed` only via `DisputeAcquire` — that's the winner's transition back. Yielders go to `Tombstoned` and stay there; their fork is dead chain.

These transitions are per-fork. The operator's main chain keeps `DisputeState = Normal` until the winner's `DisputeAcquire` is observed by clients, at which point clients stop accepting it (subsequent updates are no longer signed by the new operator) and accept the fork as canonical.

## Honest vs malicious recovery

DEP-06 distinguishes two recovery modes:

**Respectful recovery** (operator unavailable, no proven fraud). The operator may have crashed, lost their key, or gone offline indefinitely. Members can recover the deposits, but with no slashing claim — there is absence, not misbehavior. The confiscation TX sends only the *reserves* portion to the lottery output (covering ledger obligations); the *collateral* portion returns to the original operator's pubkey. The operator keeps their bond; the deposits get a new custodian.

**Punitive recovery** (proven non-conformance). A fraud proof is verified against the operator. The full UTXO — reserves plus collateral — goes to the lottery output. The winner inherits deposit obligations *and* keeps the collateral as compensation for taking them on. Excess reserves above obligations are split equally among participating quorum members. The operator gets nothing.

The two shapes are different on purpose. Respectful recovery is no-fault: honest operators are not penalized for hardware failure, key loss, or regulatory shutdown. Punitive recovery is the slashing teeth: provable misbehavior costs the entire bond plus the ledger.

The mode is determined by whether a verified fraud proof exists at confiscation time. The `Kind:9103` dispute event carries the evidence; recovery-quorum members verify before signing the confiscation TX. Missing or failing evidence defaults to respectful.

## Multi-ledger slashing

A single fraud proof against operator Alice on ledger A can be replayed against any *other* ledger Alice operates. If Alice runs A, B, and C, and there is verified evidence on A, members of B's and C's quorums can present that evidence as grounds to dispute their own respective ledgers — even though the misbehavior didn't happen there. From DEP-06 §Punitive:

> If the operator runs multiple ledgers, proof of non-conformance on one ledger can be presented to the other ledgers' quorums, triggering slashing there as well.

The protocol cannot punish "Alice the human" — only ledger-bound bonds. By treating proven non-conformance as a property of the *operator pubkey*, the protocol amplifies the cost of misbehavior in proportion to how much custody Alice was running. An operator with 10 ledgers who steals from one loses bonds on all 10. The expected payoff — at most one ledger's worth — is dwarfed by the loss.

This is what makes the network's deterrence story coherent. Without it, stealing one ledger costs one ledger's collateral; with it, multi-ledger operators face slashing across all of them, which is what makes the whitepaper's 49% coalition simulation come out unprofitable.

In implementation, multi-ledger slashing is manual escalation: a member of B's quorum, observing a verified fraud proof against Alice on A, constructs their own dispute event on B citing the A-proof as evidence. The same pipeline runs on B with its own forks, lottery, and confiscation TX. Each affected ledger is slashed independently.

## The wallet experience during recovery

A wallet holding deposits on a recovering ledger should ideally not need to do anything. The design goal is that custody changes are transparent: deposits keep their balances, transfers keep flowing, channels keep settling, only the operator pubkey rotates underneath.

The mechanics:

1. **Wallets watch for `DisputeAcquire`.** A wallet replaying the relay sees `DisputeAcquire` on a fork branch, verifies the `claim_txid` is confirmed on-chain, and switches to accepting updates signed by `new_custodian` for the same `ledger_id`.

2. **Wallets re-route requests.** Future request events (`Kind:20100`) are tagged with the new operator's pubkey; the new operator picks them up. The wallet does not need a fresh deposit-open or fresh keys — deposit state is continuous across the rotation.

3. **In-flight operations are recovered, not aborted.** A `TransferLock` outstanding at dispute time is an obligation of the ledger's operator; the new operator inherits all obligations and can fulfill or fail it the same way the old one would have. A locked but not yet credited Lightning invoice is similarly the new operator's responsibility.

4. **Ledger advertisements may be re-issued.** The operator advert (Chapter 17) carries the operator's pubkey; the new operator typically issues a fresh advert on the same `ledger_id`.

What is *not* automatic: pending Lightning channel settlements may need explicit re-anchoring if the channel anchored against the old keys, and on-chain exits in flight at confiscation time may need to be re-signed. Corner cases, covered in Chapter 9.

## Inactive-quorum slashing

The protocol also has a slashing path for a member who fails to act. If a member was demonstrably active during the dispute window — they appended updates to their *own* ledger after the fraud occurred, proving they were online — but did not initiate a dispute against the accused, they can be the target of an `InactiveQuorum` fraud proof.

The verifier (`deposits-protocol/src/fraud.rs:507::verify_inactive_quorum_member`) evaluates the member's own ledger history for activity in the window after the original fraud and the absence of a dispute event. If accepted, the member's *own* ledger is slashable.

This is the protocol's defense against passive collusion. A member who refuses to act on a fraud proof — for any reason, including private agreement with the operator — is treated as if they had committed fraud themselves, with their own collateral on the line.

This mechanism is what makes the trust assumption "at least one honest member" sufficient rather than requiring "a majority of members." Even one honest member can detect and act; any member declining to act is itself slashable, and the cost of declining cascades through the network.

## Caps and bounds

A few hard limits:

- **`MAX_DISPUTANTS = 15`** (`deposits-protocol/src/constants.rs:52`). The script construction tops out at 15. Past that, witness sizes, recovery-quorum requirements, and bond economics no longer hold. The 16th disputant receives a `DisputeFull` rejection.

- **`MAX_QUORUM_SIZE_POLICY = 8`** (`deposits-protocol/src/constants.rs:72`). The current operational policy caps total quorum size at 8 (operator + 7 cosigners), so at most 7 disputants per dispute. This is well below the script's 15-disputant cap; lifting it is a one-line constant change with no script or wire-format implications. Smaller quorums are simpler to coordinate; 8 is enough for the one-honest-member assumption to be useful without the recovery cascade dominating operations.

- **Retry depth bound** of `⌊N/2⌋` per `CUSTODY_LOTTERY.md`. Prevents an adversary controlling 2+ operators from stalling indefinitely by alternating defections across rounds. At N=7 disputants that's 3 retries; past that the lottery is declared void and falls back to manual quorum resolution.

- **Recovery-quorum precondition** `N_quorum − N_disputants ≥ T_emergency`. There must be enough non-disputing members to sign the confiscation TX, or the lottery cannot be funded. `recovery confiscate` refuses to build the lottery output if this fails — the protocol prefers a stuck dispute to a stuck UTXO.

- **Economic precondition** `disputed_value ≥ 5 × estimated_claim_fee`. If disputed value is too small relative to claim fee, the protocol refuses to arm.

## Event-driven vs polled execution

The reference daemon executes the recovery pipeline through two coupled paths: the periodic loop (which ticks every `periodic_interval` — 60s in production, 5s in fast-poll mode) and an event-driven wakeup (which fires immediately on observing a fork-branch `DisputeArmed`).

The event-driven path lives in `deposits-node/src/node/main_loop.rs:935-960`:

```rust
// Apply-edge dispute driver. When an actor signals
// `dispute_wakeup` (after observing a fork-branch
// DisputeArmed), fire `auto_confiscate` immediately instead
// of waiting for the next `periodic_interval`.
{
    let node = Arc::clone(self);
    let wakeup = self.dispute_wakeup.clone();
    tokio::spawn(async move {
        loop {
            wakeup.notified().await;
            tracing::debug!(
                "dispute_wakeup signaled — running auto_confiscate immediately"
            );
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                node.auto_confiscate(),
            ).await;
        }
    });
}
```

The wakeup is a `tokio::sync::Notify` signaled by the actor outbox drainer when any per-ledger actor emits a `MaybeConfiscate` event — which happens when an actor observes a fork-branch `DisputeArmed` and recognizes that confiscation is now possible. The event-driven path drops the armed-to-confiscate latency from 5–60s (one periodic tick) to a few milliseconds.

The periodic loop is the safety net. It runs `auto_confiscate` on schedule regardless of wakeups, so a marker missed at startup or a request timed out at 120s gets retried. Wakeup catches the common case; the periodic loop catches the edges.

The reveal, claim, and yield phases are still gated on the periodic loop. They depend on Bitcoin block confirmations or on `Kind 9106` events from other disputants, and the actor doesn't have a clean signal for either today. Making them event-driven is a follow-up; the pattern is the same `Notify` wakeup with a different trigger.

## A worked example

Q=3 ledger with operator Alice, members Bob and Carol. A wallet pays a Lightning invoice via Alice's node, gets the preimage from the LN settlement, and observes that Alice never credited the deposit. The wallet constructs an `UncreditedLightning` fraud proof, embeds the proof hash in a self-transfer's nonce on Alice's ledger, and broadcasts the `Kind:9101` event.

1. **Detect**. Bob's daemon sees the `Kind:9101` event, verifies the proof, accepts it. Carol does the same independently. Alice is excluded from the disputant set.

2. **Fork**. Bob clones the ledger up to `last_valid_seq` (sequence before the uncredited update) into a new fork keyed under a fork-key. Carol does the same — separate fork, same divergence point.

3. **Enter**. Bob appends `DisputeEnter { last_valid_sequence: 46, reason: "auto_dispute" }` to his fork. His fork's `DisputeState` is now `Disputed`. Carol does the same on hers.

4. **Arm**. Bob generates a 32-byte preimage, computes `HASH160(preimage)`, appends `DisputeArmed { armed_block, commitment_hash, target_reserves }`. Carol arms with her own preimage and address. Both forks reach `DisputeState::Armed`. Each daemon's actor outbox emits `MaybeConfiscate`, signaling `dispute_wakeup`.

5. **Confiscate**. The strict recovery quorum (members minus disputants) is empty here — Bob and Carol *are* the disputants — so the implementation cooperates with the lottery: Bob and Carol cosign the confiscation TX themselves under the small-Q emergency threshold. The TX spends Alice's reserves UTXO into the lottery output. Bitcoin confirms; each writes a `confiscated_<prefix>.marker`.

6. **Reveal**. Bob publishes `Kind:9106` carrying his preimage; Carol does the same. Each verifies the other's `HASH160(preimage)` matches the committed hash.

7. **Compute winner**. With N=2:
   - Bob's preimage: 19 bytes → contribution = 3
   - Carol's preimage: 18 bytes → contribution = 2
   - `sum = 5`, `winner_index = 5 mod 2 = 1`
   - Suppose the pubkey sort puts Bob at index 1: Bob wins.

8. **Claim**. Bob broadcasts the claim TX. The script verifies both `HASH160`s, computes `winner_index = 1`, checks the signature is Bob's. Bitcoin enforces selection — Carol's witness for the same leaf would fail at the signature check.

9. **Acquire**. Bob appends `DisputeAcquire { new_custodian: bob_pubkey, claim_txid, new_reserves_address }`. The fork's `DisputeState` returns to `Normal`. Bob is the operator; the fork is canonical.

10. **Yield**. Carol appends `DisputeYield`. Her fork is `Tombstoned` — dead chain.

11. **Cleanup**. Wallets see Bob's `DisputeAcquire`, verify the on-chain claim TX, and switch their accepted operator pubkey for `ledger_id` to Bob's. Future credits, transfers, and fee assessments are signed by Bob. Alice's collateral is gone — punitive recovery, since the original proof was verified fraud. Excess reserves above deposit obligations were split between Bob and Carol at confiscation time.

12. **Multi-ledger followup** (optional). Alice runs ledger Z with a different quorum. A member of Z's quorum cites the verified fraud proof and opens a dispute on Z. The pipeline runs again on Z. Alice's collateral on Z is also gone.

The example takes about 90 seconds in the regtest integration test, dominated by Bitcoin confirmations. Detection through `DisputeArmed` is sub-second; the wait is for the confiscation and claim TXs to confirm.

## What stays in your head

- The pipeline has six stages: *detect, fork, enter, arm, lottery, acquire*, plus cleanup. Each stage has a name corresponding to its operation type or its on-chain action.
- Disputants run forks. The operator is excluded from disputing their own ledger; disputants = (Q-1) other members. Each disputant's fork is independent; only the on-chain lottery couples them.
- The `DisputeState` per-fork transitions Normal → Disputed → Armed → (Normal | Tombstoned). The accused operator's main chain stays in `Normal` throughout — fork-branch state and main-chain state are separate.
- The lottery is on-chain. Bitcoin script, not the relay, decides the winner. Wallets must wait for the on-chain claim TX to confirm before accepting `DisputeAcquire`.
- Honest recovery is no-fault (collateral returns); proven fraud is punitive (collateral forfeited). Multi-ledger slashing replays the same proof against the operator's other ledgers, multiplying the cost of misbehavior.
- Inactive-quorum proofs slash members who failed to act. The protocol does not allow passive agreement — declining to escalate a fraud is itself slashable.
- The implementation event-drives the confiscate path via a `dispute_wakeup` Notify, dropping the armed-to-confiscate latency from 5–60s to milliseconds. The periodic loop still runs as a safety net.
- Hard caps: `MAX_DISPUTANTS = 15` (script limit), `MAX_QUORUM_SIZE_POLICY = 8` (current operational cap → ≤7 disputants per dispute), retry depth `⌊N/2⌋`, recovery-quorum precondition `N_quorum − N_disputants ≥ T_emergency`.

## Where this leads

[Chapter 13](13-custody-lottery.md) opens up the lottery itself — the commit-reveal entropy mechanism, the three script regimes by N, the partial-reveal and recovery-cascade leaves, and why the `(sum mod N)` selection is fair as long as one disputant is honest. Everything in stage 5 of this chapter is filled in there.
