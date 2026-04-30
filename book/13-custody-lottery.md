# Chapter 13: Custody Lottery

> **Audience**: developers, operators, advanced wallet users
> **Prereqs**: chapters 5, 7, 11, 12
> **DEPs**: DEP-06 (recovery), DEP-03 (on-chain TX shape)

## What problem the lottery solves

The [recovery pipeline](12-recovery-pipeline.md) is what runs after a fraud proof against an operator gets accepted: the quorum's members fork their continuation of the disputed ledger from the last conforming update, each member's fork-branch arms itself for custody takeover, and one of them eventually inherits operator status. The deposits stay in place; their custodian changes.

That last sentence hides a question. *Which* of the disputants becomes the new operator?

When only one quorum member arms — the rest are slow, offline, or uninterested — the answer is trivial: the lone armed member takes over. But in a working network, multiple members will arm. They each watched the same ledger, each saw the same fraud proof, each see an opportunity to grow their own income by acquiring a ledger that already has paying deposits on it. The protocol must pick one, and the picking has to happen on-chain — because the prize is an on-chain UTXO, and whatever mechanism decides who gets it has to be enforced by the very Bitcoin script that controls that UTXO. Anything off-chain is a coordination problem the operator's quorum has just demonstrated it can fail at.

The custody lottery is that mechanism. It is a commit-reveal randomness extraction protocol implemented as Tapscript leaves. Disputants commit to secret preimages at arm time, publish the preimages on Nostr after the operator's reserves are confiscated into a lottery-controlled output, and the lottery script enforces — at script-validation time, on-chain — that exactly one disputant can spend the output. Whoever spends it commits a `DisputeAcquire` operation on their fork-branch and becomes the new operator. The losers commit `DisputeYield` and tombstone their branches.

Because the entropy comes from secrets each disputant chose before seeing the others' commitments, and because the script is the arbiter, no off-chain agreement on the winner is required. As long as one disputant chose their preimage honestly at random, the winner is uniformly distributed, and no coalition smaller than all-of-N can bias the outcome.

This chapter walks through how that works: the commit-reveal mechanic, the three script regimes that handle different disputant counts, the partial-reveal escape hatch when a disputant goes silent, the recovery long-tail that prevents permanent freeze, and the wire-level shape of the messages that flow during a lottery round. The source of truth is `CUSTODY_LOTTERY.md` in the repository root; the implementation lives in `deposits-core/src/tapscript_reserves.rs` and `deposits-node/src/node/dispute.rs`.

## The commit-reveal mechanic

Every disputant follows three steps:

1. At arm time — when they observe a fraud proof and decide to challenge for custody — they pick a secret preimage and publish its `HASH160` (the 20-byte ripemd160-of-sha256 hash) inside a `DisputeArmed` operation on their fork-branch. The hash is on-chain-grade entropy, but it leaks zero information about the preimage's length or content.

2. After the *confiscation transaction* is mined — the on-chain transaction that spends the operator's reserves UTXO into a Tapscript output controlled by the lottery — they reveal their preimage by publishing it as a `Kind:9106` Nostr event tagged with the disputed ledger ID.

3. The winner — determined by the script's verification of which preimage was withheld in a particular spending witness — claims the output by signing the spending transaction.

The entropy comes from the *length* of the preimage. Each disputant chooses a preimage of length 17 to `16 + N` bytes, where `N` is the number of disputants. The script computes:

```
contribution_i  = LEN(preimage_i) − 16        // value in 1..=N
total           = Σ contribution_i
winner_index    = total mod N
```

The 17-byte minimum gives ~136 bits of preimage entropy, ruling out HASH160 grinding attacks where a malicious disputant might try to pre-compute a different-length preimage that hashes to the same value as their committed hash. Past that floor, the only thing the length controls is the disputant's contribution to the sum.

The commit-reveal randomness-extraction property is the standard one: as long as at least one participant chooses their preimage length uniformly at random from `1..=N`, the sum modulo N is uniform, regardless of what every other participant does. A uniform value plus anything is uniform. An honest disputant doesn't need to trust the others; they only need to trust themselves to roll a die.

The hash commitment closes the loop. HASH160 outputs are 20 bytes regardless of what the preimage is, so committing the hash leaks nothing about the chosen length. No participant can observe another's contribution before they're locked into their own.

## The lottery script in plain words

Each `DisputeArmed` operation contributes one `(commitment_hash, target_reserves, candidate_pubkey)` tuple to the eventual lottery script. When the quorum's recovery driver (`recovery_confiscate`) is ready to broadcast the confiscation transaction, it gathers all such tuples observed for the disputed ledger and builds a Tapscript leaf that hard-codes them into the spending conditions.

The leaf script, in the simplest form, looks roughly like this:

```
// Stack on entry: <sig> <preimage_N> ... <preimage_2> <preimage_1>

// For each disputant i in 1..N:
OP_DUP OP_HASH160 <commitment_hash_i> OP_EQUALVERIFY  // verify preimage hashes correctly
OP_SIZE 16 OP_SUB OP_TOALTSTACK                       // contribution_i = len - 16
OP_DROP                                               // discard preimage

// Sum the N contributions popped from altstack
OP_FROMALTSTACK OP_FROMALTSTACK OP_ADD
... (N − 1 ADDs total) ...

// Compute sum mod N (some opcode sequence — the choice
// of subtraction or table-lookup is the regime decision)
...

// Dispatch to candidate_(sum mod N)'s pubkey
OP_DUP 0 OP_EQUAL OP_IF OP_DROP <candidate_pubkey_0> OP_CHECKSIG
OP_ELSE OP_DUP 1 OP_EQUAL OP_IF OP_DROP <candidate_pubkey_1> OP_CHECKSIG
... (N arms) ...
OP_ENDIF OP_ENDIF ...
```

Several things to notice about the shape of this script:

- **The script enforces preimage validity.** Each `OP_HASH160 <h_i> OP_EQUALVERIFY` rejects a witness where the i-th preimage doesn't hash to the i-th committed hash. A disputant cannot substitute a different preimage of a different length to bias the sum.
- **The script enforces preimage length range.** The contribution `OP_SIZE OP_16 OP_SUB` becomes a stack value that's only positive if the preimage is at least 17 bytes; the dispatch only matches indices `0..N`, so an out-of-range contribution dead-ends. Off-chain validators (`LotteryOutput::calculate_winner` in `tapscript_reserves.rs`) enforce the upper bound `16+N`, but the script also does because contributions outside that range produce sums outside the dispatch table.
- **The script enforces winner identity.** Only one candidate's pubkey is selected by the `(sum mod N)` dispatch arm, and only that candidate's signature passes `OP_CHECKSIG`. Anyone else trying to spend with the same witness would fail signature verification on the wrong pubkey.

So the witness — `<sig> <preimage_N> ... <preimage_1>` — is constrained in three ways: the preimages must hash correctly, must compute a sum that selects exactly one candidate, and the signer must be that candidate. There's no way for a non-winner to spend the output.

## Three regimes by N

The shape of the dispatch and the modulo computation depend on `N`. Three regimes split the range `3..=15`. The selector lives at `LotteryScriptBuilder::build_lottery_script` in `deposits-core/src/tapscript_reserves.rs:887`.

**Regime A — Linear (N ≤ 5).** Compute `sum mod N` by iterated subtraction (subtract `N` until the value is below `N`), then dispatch on the index with a linear `OP_DUP <i> OP_EQUAL OP_IF ... OP_ELSE` cascade. At N=3 the leaf is around 300 bytes; at N=5, around 600. The script is linear in `N` end to end.

**Regime B — Combined dispatch table (N = 6..10).** At higher N, the linear `if/elif` cascade of `N` arms wastes bytes: each arm has its own `OP_DUP`, `OP_EQUAL`, `OP_IF`, `OP_DROP`. A more efficient construction skips the modulo entirely. The sum lies in `[N, N²]`, so the script emits one dispatch arm per *distinct sum value*, each pointing directly at `candidate_pubkey_(sum mod N)`. The modulo is folded into the dispatch table at construction time. Arm count is `N² − N + 1` (31 at N=6, 91 at N=10), which is byte-for-byte competitive with separate-mod-then-dispatch through about N=10.

**Regime C — Linear-after-mod (N = 11..15).** Past N=10, the combined table grows quadratically and stops paying off. The construction switches back to explicit `sum mod N` followed by linear dispatch — the same shape as Regime A, just with more arms. At N=15 the leaf is ~1.2 KB.

An earlier draft of the design specified a balanced binary tree for Regime C on the asymptotic argument that O(log N) tree depth beats O(N) linear chain. That argument doesn't pay off at this size: total bytes are dominated by the N pubkey leaves (`<pubkey> OP_CHECKSIG` is ~38 bytes), not by the comparison ops, so a tree saves only the structural difference between `OP_DUP <i> OP_EQUAL OP_IF` and `OP_DUP <threshold> OP_GE OP_IF`. Linear-after-mod also shares its dispatch shape with Regime A, halving the builder code path. Regime C exists as a separate label not because the script is structurally different from A, but because the *operational envelope* is different: at N≥11, partial-reveal claim leaves are added, recovery is the expected mode, and bond economics tighten.

The dispatch summary, with measured leaf sizes:

| N    | Dispatch       | Mod      | Leaf size |
|------|----------------|----------|-----------|
| 3-5  | Linear         | Subtract | ~300-600 B |
| 6-10 | Combined table | (folded) | ~1.5-4.3 KB |
| 11-15 | Linear         | Subtract | ~0.8-1.2 KB |

The Q≤8 policy cap (see [Chapter 7](07-quorum-and-collateral.md)) caps disputant counts at `Q − 1 = 7` because the original operator is structurally barred from disputing their own ledger. So in practice every lottery on a real ledger lands in Regime A or B; Regime C is a script-level capability that exists for forward compatibility when the cap lifts. Tests at N=11, N=15 still validate the script-side machinery, but the operational paths the daemon walks every day live in N=2..7.

## Worked example: 3 disputants

To make the mechanics concrete, here is what an N=3 lottery looks like end to end. Suppose Alice, Bob, and Carol are quorum members of a ledger whose operator just got caught by a fraud proof. All three arm.

**Step 1 — commitments.** Each picks a preimage:

- Alice picks `X` of length 17 bytes (contribution = 1)
- Bob picks `Y` of length 18 bytes (contribution = 2)
- Carol picks `Z` of length 19 bytes (contribution = 3)

Each broadcasts a `DisputeArmed` operation on their fork-branch:

```
DisputeArmed {
    armed_block:      900_142,
    commitment_hash:  HASH160(X),    // for Alice; Y for Bob, Z for Carol
    target_reserves:  "bcrt1p...",   // each disputant's destination address
}
```

The original operator does not arm. They have nothing left to win — their ledger is being taken from them. Their quorum members do.

**Step 2 — confiscation.** A quorum member whose recovery driver is caught up runs `recovery confiscate`. The driver reads all observed `DisputeArmed` events for the disputed ledger, gathers their `(commitment_hash, target_reserves, candidate_pubkey)` tuples in a deterministic order, and builds a `LotteryOutput` whose Taproot tree contains:

- A primary lottery leaf encoding all three commitments and pubkeys
- Three recovery leaves at CSV 144 / 1008 / 4032 with descending thresholds, allowing the quorum-minus-disputants to sweep funds back to reserves if the lottery stalls
- A timeout-recovery leaf at CSV 8064 (~8 weeks) with threshold 1, an escape hatch that any single recovery voter can use after extreme delay

(Partial-reveal leaves only appear at N≥11, so they're absent here.)

The quorum builds and signs a confiscation transaction that spends the operator's reserves UTXO into this `LotteryOutput`. Each member must collect a threshold number of cosignatures from their peers — the same threshold the original reserves UTXO required. Once the confiscation TX is mined, the on-chain prize is locked into the lottery script.

**Step 3 — reveals.** Alice, after observing the confiscation TX confirm, publishes a `Kind:9106` (`KIND_CUSTODY_LOTTERY_REVEAL`) Nostr event:

```json
{
    "ledger_id":     "<disputed ledger ID>",
    "preimage_hex":  "<hex of X>",
    "member_pubkey": "<Alice's pubkey>",
    "signature":     "<sig over SHA256('CustodyLotteryReveal:' || ledger_id || 0x00 || X)>"
}
```

Bob does the same with `Y`. Now the network can compute `sum = 1 + 2 + contribution_carol`. If Carol also reveals `Z`, all three preimages are public, the sum is `1 + 2 + 3 = 6`, and `6 mod 3 = 0` — Alice wins.

**Step 4 — Carol withholds.** But suppose Carol calculates that withholding `Z` and instead spending the lottery output herself would pay off. With Alice's and Bob's preimages public, Carol can construct a witness:

```
<carol_sig> <preimage_Z> <preimage_Y> <preimage_X>
```

She submits the spending transaction. The script:

1. Pops `X`, hashes it, verifies `HASH160(X) == commitment_hash_alice`. OK. Pushes `len(X) − 16 = 1` to altstack.
2. Pops `Y`, verifies. Pushes `len(Y) − 16 = 2` to altstack.
3. Pops `Z`, verifies. Pushes `len(Z) − 16 = 3` to altstack.
4. Sums altstack: `1 + 2 + 3 = 6`.
5. Computes `6 mod 3 = 0`.
6. Dispatches to candidate-0's pubkey — Alice's.
7. `OP_CHECKSIG` against Alice's pubkey, with Carol's signature on top of the stack. **Fails.**

Carol cannot spend — the script enforces the winner. So she has no incentive to withhold; her best move is to reveal `Z` (or accept defeat by yielding) so that the lottery completes and *somebody* gets the prize. Eventually Carol publishes `Z`, Alice constructs the same witness with her own signature, and Alice wins.

**Step 5 — Acquire and Yield.** Once the lottery output is spent, Alice broadcasts a `DisputeAcquire` operation on her fork-branch:

```
DisputeAcquire {
    new_custodian:        <Alice's pubkey>,
    claim_txid:           <txid of the lottery-claim transaction>,
    new_reserves_address: "bcrt1p...",   // Alice's target_reserves
}
```

The `claim_txid` is the on-chain proof that Alice's branch is the rightful continuation of the ledger. Anyone replaying the chain can verify on-chain that this transaction spends the lottery output, and the lottery output's script enforces that only Alice could have signed it.

Bob and Carol broadcast `DisputeYield` on their respective branches:

```
DisputeYield
```

This is a minimal terminator — no payload. It tombstones the branch, signaling that wallets and downstream peers should disregard further updates on it. Alice's branch is now the canonical ledger; the original operator's chain (and Bob's and Carol's branches) are dead.

What's important to notice: the on-chain `claim_txid` is the *only* proof of who won. The `DisputeAcquire` operation on Alice's branch is just bookkeeping — recording on the ledger what the Bitcoin layer has already enforced. If Bob tried to publish a `DisputeAcquire` on his branch, members validating the chain would reject it: `claim_txid` would point to a transaction that doesn't pay Bob's `target_reserves`, and the validator would refuse to apply it. The validator code (`Ledger::validate_operation`) doesn't even need to compute the lottery winner — it just checks that `new_custodian` is in the candidate set and `claim_txid` is non-zero. The Bitcoin layer guarantees the rest.

## Partial-reveal witnesses

The N=3 example above relied on every disputant eventually revealing their preimage. At higher N this assumption gets weaker. By N=10 with 95% per-party reveal probability, P(all reveal) is around 60% — recovery is a normal mode of operation, not an exception. By N=15, recovery is more likely than completion.

The protocol's first response to a missing reveal is a *partial-reveal claim leaf*: a Tapscript leaf that runs an (N−1)-party lottery among the remaining disputants, after a CSV-72 (~12 hour) timeout to give the missing disputant a chance to catch up. For N≥11, the Taproot tree gains N additional leaves, one per possible "missing" disputant index. Each leaf is structured as:

```
72 OP_CHECKSEQUENCEVERIFY OP_DROP
<lottery script for (N−1)-party lottery excluding disputant j>
```

The (N−1)-party sub-lottery uses the regime appropriate for `N−1`, not `N`. So at N=11 each partial leaf is a Regime B (combined-table) lottery for 10 parties; at N=15 each partial leaf is a Regime C (linear-after-mod) lottery for 14 parties. The witness construction helper `LotteryOutput::create_partial_reveal_witness(missing_idx, sig, preimages)` mirrors `create_claim_witness` but takes only `N − 1` preimages and selects the appropriate leaf via Taproot control block.

The cap at K=1 — "exactly one disputant missing" — is a Tapscript constraint, not an arbitrary limit. Tapscript has no bitmap dispatch (`OP_AND`, `OP_OR`, `OP_LSHIFT`, `OP_RSHIFT` are all disabled `OP_SUCCESS` opcodes), so each "shape" of partial-reveal lottery has to be its own leaf. K=1 adds N leaves; K=2 would add `C(15, 2) = 105` leaves at N=15; K=3 would add 455. K=1 covers the dominant failure mode at any plausible reveal reliability:

| p (per-party) | P(K=1 missing) | P(K≥2 missing) | K=1 covers |
|---|---|---|---|
| 0.99 | 13% | 1% | ~99% of failures |
| 0.95 | 37% | 17% | ~70% of failures |
| 0.90 | 34% | 45% | ~45% of failures |

If production reveal reliability turns out worse than ~0.95, K=2 leaves are a pure construction-time extension to add — no protocol or message changes required, just more leaves at construction time and a new helper. The wire format already accommodates the extra leaf count.

The K=1 leaves are present in `LotteryOutput::partial_reveal_scripts: Vec<ScriptBuf>` at construction time; the helper `create_partial_reveal_witness` is in `tapscript_reserves.rs:1326`. At N=15 the Taproot tree has 20 leaves total (1 primary + 15 partial-reveal + 4 recovery), with Merkle depth 5, adding ~160 bytes to the witness for the control block.

## Recovery long-tail

Cases not covered by K=1 — two or more disputants silent — fall through to a long-tail recovery structure that mirrors the reserves output's emergency leaves. Each recovery leaf has a longer CSV timeout than the previous and a lower threshold:

```
Recovery leaf k:
  <csv_blocks_k> OP_CHECKSEQUENCEVERIFY OP_DROP
  <threshold_k> <quorum_pubkeys_minus_disputants> OP_CHECKMULTISIG
```

The implementation builds three primary recovery leaves at CSV 144 (~24 hours), CSV 1008 (~1 week), and CSV 4032 (~4 weeks), with thresholds T, T−1, T−2 respectively. A fourth leaf at CSV 8064 (~8 weeks) with threshold 1 is the timeout-recovery escape hatch added in Phase 4c — the on-chain artifact for "the dispute has been declared void." Any single recovery voter can sweep the lottery output back to reserves through that leaf if every other path fails.

The disputants are *excluded* from all recovery paths. They had their chance and either failed to take custody (because the lottery selected someone else) or failed to maintain the responsiveness of the dispute pipeline (because they didn't reveal). The recovery vote belongs to the rest of the quorum.

The trade-off: the long-tail extends the dispute window — funds may be unspendable for weeks if the worst-case path runs to completion — but it eliminates the possibility of a permanent freeze. As long as at least one recovery voter is alive after CSV 8064, the funds eventually return to circulation.

The recovery-quorum precondition — `N_quorum − N_disputants ≥ T_emergency`, enforced in `recovery_confiscate` — is a hard gate on this structure. Without it, the long-tail leaves would have insufficient signers and the funds *could* freeze. The check refuses to build the lottery output unless the precondition holds. With the Q≤8 policy cap, the worst-case is `8 − 7 = 1` recovery voter, which clamps `T_emergency` to 1 and keeps the leaf well-formed.

## Reveal events

`KIND_CUSTODY_LOTTERY_REVEAL = 9106` carries the preimage announcement (`deposits-node/src/nostr.rs:106`). The kind sits in the durable range (1000–9999), not the ephemeral range (20000+), and that distinction matters: late joiners need to be able to fetch reveals well after the publishing disputant has gone offline. If the events were ephemeral, a relay restart between publish and claim could lose the data and force the lottery into a partial-reveal or recovery path.

The event's content is a JSON object with `ledger_id`, `preimage_hex`, `member_pubkey`, and a signature over `SHA256("CustodyLotteryReveal:" || ledger_id || 0x00 || preimage)`. The signature binds the reveal to the disputant's identity, preventing a third party from cribbing a preimage from a leaked source and re-publishing it under their own pubkey to fake an arming. The verifier (currently scaffolded but not wired into the production claim path — see Phase 5c notes in `CUSTODY_LOTTERY_PLAN.md`) checks the signature before accepting the preimage into the winner calculation.

Each disputant's daemon publishes its own preimage automatically via `auto_reveal_on_confiscation` once it observes the confiscation TX in the mempool or a block. The CLI command `recovery reveal <ledger_id>` is the manual fallback.

## Claim or yield, the disputant's choice

After reveals are out, every disputant's daemon runs `auto_lottery_claim_or_yield` (`deposits-node/src/node/dispute.rs:364`) periodically — and on event-driven wakeup when fresh reveals arrive on Nostr. The function:

1. Fetches all reveals for the ledger ID.
2. Validates each reveal's signature.
3. Calls `LotteryOutput::calculate_winner(&preimages)` to compute the index.
4. If the winner index matches the daemon's own pubkey: build the claim transaction, broadcast it, and emit a `DisputeAcquire` operation on the daemon's fork-branch with the resulting `claim_txid`.
5. Otherwise: emit a `DisputeYield` operation on the fork-branch.

The claim path requires the daemon's BDK wallet to construct a P2TR-spending transaction with the right witness (`LotteryOutput::create_claim_witness` at `tapscript_reserves.rs:1421`), broadcast it, and confirm it onto the chain. The yield path requires only a one-byte ledger update — `DisputeYield` carries no payload. Both end the dispute as far as the disputant is concerned: a completed-marker file in the data directory keeps the auto-task from re-running.

The two operations land on the disputant's *fork-branch* of the ledger, not the original operator's chain. Each branch is a parallel append-only history that diverged from the same `last_conforming_update`; whichever branch ends with `DisputeAcquire` and a verifiable `claim_txid` is the canonical continuation. The other branches end with `DisputeYield` and become epitaphs.

## Wire format summary

The three operations the lottery introduces or modifies:

```rust
// In deposits-protocol/src/messages/types.rs
pub enum LedgerOperation {
    // ...
    DisputeArmed {
        armed_block: u32,
        commitment_hash: [u8; 20],     // HASH160 of the disputant's secret preimage
        target_reserves: String,       // address where the lottery prize should land
    },
    DisputeAcquire {
        new_custodian: PublicKey,      // the lottery winner
        claim_txid: [u8; 32],          // the on-chain claim TX, spending the lottery output
        new_reserves_address: String,  // matches the winner's target_reserves
    },
    DisputeYield,                      // no payload — tombstones the branch
}
```

The `DisputeAcquire` shape is current as of late 2025, after a hard wire-format break that dropped two fields the old entropy-block-hash construction needed (`entropy_block_height` and `entropy_block_hash`). The on-chain script now enforces winner selection, so the state machine doesn't need to carry the winning-block evidence — it only needs the `claim_txid` linking the ledger update to its on-chain witness.

The reveal message is not a `LedgerOperation` — it doesn't land on any ledger. It's a peer-to-peer Nostr event. Wire shape:

```json
{
    "ledger_id":     "<32-byte hex>",
    "preimage_hex":  "<hex>",
    "member_pubkey": "<33-byte compressed pubkey hex>",
    "signature":     "<64-byte Schnorr sig hex>"
}
```

Published as a `Kind:9106` Nostr event tagged with `TAG_LEDGER_ID` and `member`, durable, with the disputant's pubkey as the event's `pubkey` field for relay-level filterability.

## Hard limits and bounds

The protocol enforces these in code, not just documentation:

- **`MAX_DISPUTANTS = 15`** (`deposits-protocol/src/constants.rs`). The 16th candidate's `DisputeArmed` is rejected; the script-level cap also fires if the recovery driver tries to build a script for too many. This is the cap at which the construction stops being the right tool — past 15, witness sizes, recovery-quorum requirements, and bond economics all stop scaling.
- **`MAX_QUORUM_SIZE_POLICY = 7`** with `VALID_QUORUM_SIZES = {3, 5, 7}` (also `constants.rs`). `Q` is the cosigner count; the operator is *not* counted. Disputants = `Q` exactly (every cosigner can dispute; the operator is barred from disputing their own ledger and was never in `Q`). This policy is what holds today; lifting the cap or extending the allowed set is a one-line constant change with no script or wire-format implications.
- **`PARTIAL_REVEAL_MIN_N = 11`**. Below this, the partial-reveal leaves are absent from the Taproot tree. The cost of K=1 leaves (N additional leaves at CSV 72) is justified only when reveal reliability statistics make recovery a likely outcome; at N≤10 the simpler structure is cheaper and the recovery long-tail handles the rare missing reveal.
- **`PARTIAL_REVEAL_CSV_BLOCKS = 72`**, **`TIMEOUT_RECOVERY_CSV_BLOCKS = 8064`**. Approximately 12 hours and 8 weeks at 10-minute block intervals.
- **Recovery-quorum precondition**: `recovery_confiscate` refuses to build the lottery output unless `N_quorum − N_disputants ≥ T_emergency`. Without this, a stalled high-N lottery could be unrecoverable.
- **Economic precondition**: if `disputed_value < 5 × estimated_claim_fee`, the lottery is uneconomical and the protocol refuses to arm. There's no point spending more in fees than the prize is worth.

The retry-depth bound (`⌊N/2⌋` rounds before a dispute is declared void) is recorded in the design but currently unimplemented at the orchestration layer; the on-chain CSV-8064 timeout-recovery leaf is the artifact that will eventually catch a void dispute. See Phase 5f in `CUSTODY_LOTTERY_PLAN.md`.

## Why this works

The lottery's security properties, in one paragraph each:

**Fairness.** The randomness extraction holds as long as one participant is honest. The script enforces preimage validity and length range; the modular sum is a one-time pad over the residues. No coalition smaller than all-of-N can bias the outcome, because every other disputant's contribution is uniform-or-better from the honest party's perspective.

**Atomicity.** Either the primary lottery completes (all reveal), a K=1 partial-reveal leaf claims the output (one missing), or the recovery long-tail returns funds to the quorum-minus-disputants. No path leaves the funds permanently stuck, provided the recovery-quorum precondition holds at construction time.

**Verifiability.** Anyone watching the chain can verify the winner from the on-chain claim transaction's witness — the preimages are publicly visible, the script's modular arithmetic is deterministic, the candidate pubkeys are encoded in the script bytes. There's no black-box randomness oracle.

**Trustlessness.** No off-chain agreement on the outcome is required. The losers can `DisputeYield` voluntarily because they have nothing to gain by stalling, but if they don't yield, their fork-branches simply remain without a `DisputeAcquire` and observers correctly identify the winner's branch as canonical by the on-chain proof.

The trade-off the protocol makes: by relying on a commit-reveal mechanic, the lottery requires N rounds of communication (commit, reveal, claim) and tolerates only a CSV-72-bounded silent disputant before falling back to partial-reveal, then to longer recovery paths. Compared to a deterministic VRF or block-hash beacon, it is slower and more communication-intensive. Compared to off-chain coordination, it is *trustless* — and that's the whole point. The disputed ledger's quorum has just demonstrated it can fail; building the dispute resolution on top of that same quorum's coordination would be self-defeating.

## Where this leads

The lottery handles the case where multiple operators race to take over a single misbehaving ledger. The next chapter, [Chapter 14: Equivocation Defense](14-equivocation-defense.md), covers the failure mode the lottery cannot deter on its own: an operator who signs two contradictory updates at the same sequence number, presenting different chains to different observers. Equivocation can't be ruled out cryptographically — anyone with the operator key can produce a contradictory signature — so the protocol's defense lies in late-discovery slashing and a network-wide rule that the first conforming chain to reach a quorum's collateral attestation is the one that survives.
