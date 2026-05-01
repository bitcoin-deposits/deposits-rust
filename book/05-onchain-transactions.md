# Chapter 5: On-Chain Transactions

> **Audience**: operators, developers, advanced wallet users
> **Prereqs**: chapters 2, 3 (Taproot section), 4
> **DEPs**: DEP-03

The protocol is mostly off-chain. Wallets deposit, transfer, pay invoices, and receive — none of those touch Bitcoin directly. What does touch Bitcoin is the small, slow heartbeat of on-chain activity that anchors the whole network: the operator's reserves UTXO, the rotations that keep it aligned with quorum membership, the confiscation transactions that fire during a dispute, and the rare cooperative withdrawals where a depositor cashes out to mainchain. This chapter walks through those transactions and the Taproot script tree that controls every one of them.

The single most important fact to keep in mind: **a ledger has exactly one on-chain UTXO at a time.** No fan-out per deposit, no per-transfer transactions, no Lightning-style commitment broadcasting. One Taproot output, jointly controlled by the quorum, holds the whole ledger's value — both the reserves the depositors are entitled to and the operator's own collateral bond. That output gets spent only when the protocol genuinely demands it: rotation at quorum refresh, confiscation during a dispute, or a cooperative on-chain exit. Everything else is signatures over JSON, broadcast on Nostr.

## What's in the UTXO

A reserves UTXO is a P2TR output with the following accounting structure (negotiated and recorded in the `QuorumBegin` operation that anchored it — see [Chapter 4](04-ledger-state.md)):

```
+------------------------------------------+
| reserves_amount_msats   (deposit cap)    |
| collateral_amount_msats (security bond)  |
+------------------------------------------+
| on-chain value (sats) =                  |
|   (reserves + collateral) / 1000         |
+------------------------------------------+
```

Reserves are the deposit capacity: total open-deposit balances on the ledger cannot exceed this. Collateral is the operator's at-risk bond — capital they put up so that misbehaving costs them more than the upside of the misbehavior. The split is a deployment parameter; the reference recommendation is 40/60 reserves-to-collateral, but the protocol enforces only that `reserves + collateral` equals the actual on-chain value, not the ratio. See [PROPOSAL.md](../PROPOSAL.md) for why collateral lives in the same UTXO and not in side deposits on member ledgers.

A wallet auditing the ledger doesn't trust the operator's claim about the split. It reconstructs the expected `scriptPubKey` from the public quorum membership and the ledger hash recorded in `QuorumBegin`, then compares against the on-chain UTXO. If the script-pubkey matches, the wallet has cryptographic evidence that the value bytes go through the script tree the protocol expects. The reconstruction logic lives in `deposits-core/src/tapscript_reserves.rs` (`build_taproot_reserves_script`, `verify_taproot_reserves`).

## The script tree

The reserves UTXO uses a Taproot output with **no key-path spend** — the internal key is the BIP-341 NUMS point (`0x509...3ac0`, lifted from `SHA256("TapTweak")`), which has no known discrete log. Anyone who tries to claim a key-path signature must produce a private key for a point that, by construction, has none. Wallets verify this on every `QuorumBegin` (`verify_nums_internal_key` at `deposits-core/src/tapscript_reserves.rs:48`) and refuse to deposit against any reserves output where the internal key is anything else, because a non-NUMS internal key would let whoever knows its private key key-path-spend the UTXO and bypass every other protection in the tree.

All spending therefore goes through script-path reveals. The tree contains tiered leaves with progressively looser thresholds and progressively longer timelocks:

| Tier | Signers | CSV timelock | When this fires |
|---|---|---|---|
| 0 | Majority of quorum (operator excluded) | 0 | Cooperative reserves rotation, settlements |
| 1 | Minority of quorum (~⌊n/3⌋) | 1008 blocks (~1 week) | Degraded recovery when members are down |
| 2 | Operator only | 2016 blocks (~2 weeks) | Operator solo if quorum is unresponsive |
| 3 | Any single party | 4032 blocks (~4 weeks) | Emergency last resort |

Plus an unspendable leaf that commits the ledger hash into the tree:

```
<ledger_hash> OP_DROP OP_FALSE
```

This leaf can never be satisfied (it ends in `OP_FALSE`), but it is part of the Merkle root. So the on-chain `scriptPubKey` is a function of the quorum's pubkeys, the timelock policy, *and* the ledger hash. Any wallet that knows the ledger hash and the quorum membership at a given `QuorumBegin` can recompute the expected P2TR address and compare with the on-chain UTXO. If the operator commits to a different `ledger_hash` in their off-chain `QuorumBegin` than the one baked into the on-chain script, the addresses don't match and the wallet has provable evidence of inconsistency. This is the cheap, non-relay-dependent state checkpoint mentioned in DEP-03 §On-Chain State Anchor — it costs nothing extra at funding time and gives wallets a way to detect relay censorship or operator drift without trusting any single relay's history.

Each Tier 0/1 leaf uses BIP-342 `OP_CHECKSIGADD` aggregation rather than `OP_CHECKMULTISIG`:

```
<key_1> OP_CHECKSIG
<key_2> OP_CHECKSIGADD
<key_3> OP_CHECKSIGADD
...
<threshold> OP_GREATERTHANOREQUAL
```

The keys are sorted lexicographically so that any party building the script ends up with the same bytes. The operator is deliberately excluded from Tiers 0 and 1: those tiers exist for the *quorum*, not the operator. A quorum that no longer trusts the operator must be able to rotate or recover the UTXO without operator participation. The operator's solo path lives at Tier 2 with a two-week wait, which is long enough for the quorum to act first if they have any reason to.

The two-party special case (`n ≤ 2`) collapses Tiers 0 and 1 into a single 2-of-2 leaf, since splitting majority-from-minority makes no sense at that size.

The full tree-builder, including how leaves get assigned depths so that more-common spend paths have shorter Merkle proofs, is at `TapscriptReservesBuilder::build` in `deposits-core/src/tapscript_reserves.rs:367`.

## Funding the UTXO

The first thing a new operator does on-chain is open a reserves UTXO. Concretely:

1. The operator and their prospective quorum members negotiate membership and the reserves/collateral split off-chain (`QuorumAddMember` operations on the ledger record the staging — see [Chapter 7](07-quorum-and-collateral.md)).
2. The operator gathers the `reserves_amount + collateral_amount` of BTC in their hot wallet (BDK, in the reference daemon).
3. The operator builds the Taproot output: voter set = quorum members (operator is *not* a voter for Tier 0/1), tier config = the default for `n` voters, `ledger_hash` = the chain hash at the staging point.
4. The operator broadcasts a transaction with one P2TR output to that address. The transaction also carries an `OP_RETURN` output containing the 32-byte ledger hash, providing an independent on-chain checkpoint anyone can verify against the relay.
5. After the configured confirmation depth (6 mainnet, 3 testnet/signet, 1 regtest — see DEP-03 §QuorumBegin), the operator publishes a `QuorumBegin` ledger update referencing the new outpoint.
6. Each prospective cosigner verifies, against their own chain source, that the outpoint exists, is unspent, has value equal to `(reserves + collateral) / 1000`, and is sufficiently confirmed. Only then do they cosign the `QuorumBegin`. A cosigner who can't verify against their own chain refuses to cosign — the operator's collector waits for another responder or times out. This is the protocol's defense against a malicious operator pointing `QuorumBegin` at a fake or undervalued outpoint.

Once `QuorumBegin` is committed, the ledger is "active" — the quorum is the on-chain authority for the UTXO, and from this point on every ledger update (deposits, transfers, fees, future rotations) requires a quorum-majority cosignature. Reserves are the deposit cap; collateral cannot back deposits; the conformance checks the operator's actor runs before staging any operation enforce both invariants.

## Reserves rotation

Quorums are not permanent. Each member's `QuorumAddMember` carries a `membership_until` block height; the quorum's overall expiry is the *minimum* of those, because the script tree can only encode one timelock and the most-impatient member sets the deadline. Before that block arrives, the operator must roll the UTXO into a new one with a fresh `QuorumBegin`. Membership churn — a member leaving, a new member joining, a `Q ∈ {3, 5, 7}` reshuffle — also forces a rotation, since it changes the script tree.

A rotation transaction is shaped like this:

```
INPUT:                                       OUTPUTS:
  outpoint of current reserves UTXO          [0] new reserves UTXO (P2TR, new ledger_hash)
  witness: Tier 0 — majority quorum sig          value = old_value - fee
  control block reveals Tier 0 leaf          [1] OP_RETURN <chain_hash>  (32 bytes)
                                             [2] (optional) operator change for fee
```

The operator's actor builds the unsigned transaction, passes it to the per-ledger cosign coordinator, collects ⌊n/2⌋+1 Schnorr signatures from quorum members over the BIP-341 sighash, assembles the witness, and broadcasts. After the confirmation depth, the operator publishes a `QuorumBegin` referencing the new outpoint; cosigners verify and re-cosign. **The `QuorumBegin` itself carries cosignatures**, just like every other update once a quorum is active — there is no special bootstrapping exception, the only difference is that a cosigner verifying the *first* `QuorumBegin` of a brand-new ledger has nothing prior to compare it against. Subsequent rotations are validated against the immediately-prior reserves state.

Three timing constraints that bite operators:

- The new outpoint must have at least the configured confirmation depth before cosigners will sign the rotation `QuorumBegin`. Wait for blocks before staging.
- The rotation must complete *before* `quorum_expiry`. Past that, Tier 2 (operator-solo) starts becoming reachable — but the operator reaching Tier 2 is the recovery path of last resort, not a planned rotation.
- Fee handling: the operator covers the rotation fee from their own funds, but the fee comes out of the UTXO's on-chain value, which means `new_value = old_value − fee`. The accounting split (reserves vs. collateral) typically holds reserves constant and pulls the fee from collateral, but this is policy, not protocol. The operator records the new amounts in the new `QuorumBegin`; cosigners re-verify the on-chain value against them.

In a working network, rotation is a quiet ~weekly event that nobody outside the operator's daemon notices. It shows up in the ledger as one `QuorumBegin` update; on the chain as one P2TR-to-P2TR spend with a small `OP_RETURN`.

## Confiscation: the dispute path

The dispute path is the only on-chain path that does not start with cooperation. When a [fraud proof](11-fraud-proofs.md) fires against the operator, the quorum abandons the cooperative cosign relationship and uses the *script path* to take the UTXO away. Disputants — quorum members who entered the dispute via `DisputeEnter` — race a [custody lottery](13-custody-lottery.md), and the lottery winner becomes the new operator.

The mechanics happen in two transactions:

**Transaction 1: confiscation (quorum spends old UTXO into a lottery output).**

```
INPUT:                                       OUTPUTS:
  current reserves UTXO                      [0] lottery output (P2TR, new tapscript tree)
  witness: Tier 0 — majority quorum sig          encodes commitment_hash + target_reserves
                                                 for each disputant; carries `obligations`
                                                 worth of reserves
                                             [1..] change distribution:
                                                 - respectful (QuorumExpired): single
                                                   output, (excess + full collateral) →
                                                   operator's pubkey
                                                 - punitive (any other fraud-proof type):
                                                   Q outputs, (excess + collateral)/Q each
                                                   → each cosigner's pubkey
```

This transaction is built and cosigned by the *recovery quorum* — quorum members minus disputants minus the disputed operator. The operator is excluded from cosigning because they are the party being confiscated. Disputants are excluded because they are competing for custody and shouldn't have authority over how the lottery output gets shaped.

The lottery output is a *different* Taproot output than the original reserves. Its tree (full structure in DEP-03 §Lottery Output Tapscript Tree and CUSTODY_LOTTERY.md) contains:

- **Leaf 0 — primary lottery claim.** A script that consumes all N preimages, hashes each against its committed `commitment_hash`, derives each contribution as `LEN(preimage) − 16`, sums them, computes `sum mod N`, and dispatches via `OP_CHECKSIG` to the pubkey of the matching disputant. The dispatch shape changes by N: linear `if/elif` for N ∈ 2..=5 and 11..=15, a combined-table dispatch (one arm per distinct sum value, folding the modulo into the table) for N ∈ 6..=10. `LotteryScriptBuilder::new` at `deposits-core/src/tapscript_reserves.rs:863` picks the regime automatically.
- **Leaves 1..=N (only for N ≥ 11) — partial-reveal claim leaves.** One per missing-disputant index, each prefixed with `72 OP_CHECKSEQUENCEVERIFY OP_DROP` and containing an (N−1)-party lottery script that excludes that specific disputant. These exist because at high N the probability of all disputants revealing in time drops sharply — at N=15 with 95% per-party reveal reliability, only ~46% of rounds complete the all-reveal happy path. The K=1 partial-reveal leaves cover the dominant "exactly one missing" failure mode after a 12-hour CSV. Two-or-more missing falls through to the long-tail recovery path. `LotteryOutput::create_partial_reveal_witness` at `deposits-core/src/tapscript_reserves.rs:1326` builds the witness for these.
- **Long-tail recovery cascade.** Three CSV-gated multisig leaves at 144, 1008, and 4032 blocks, with descending thresholds (T, T−1, T−2) over the recovery quorum. These exist to make sure the lottery output never permanently strands funds: even if every disputant goes silent, the recovery quorum can sweep at CSV 144; if some recovery members are also offline, lower thresholds become available at later timelocks.
- **Timeout-recovery escape hatch.** A CSV-8064 (~8 weeks) leaf with threshold 1 — any single recovery voter can sweep. Last-resort.

Internal key: NUMS again. No key-path on the lottery output either.

**Transaction 2: claim (winner spends lottery output to their own reserves).**

After the confiscation tx confirms, each disputant publishes their preimage as a `CustodyLotteryReveal` on Nostr (Kind 9106). Once all N preimages are observed, anyone can compute the winner — `(Σ (LEN(preimage_i) − 16)) mod N`. The winner constructs a claim transaction:

```
INPUT:                                           OUTPUT:
  lottery UTXO                                   [0] new reserves UTXO at winner's
  witness:                                           target_reserves address
    [signature_winner]   (bottom of stack)           value = lottery_value - fee
    [preimage_{N-1}]
    ...
    [preimage_0]
    [leaf_0_script]
    [control_block]
```

`LotteryOutput::create_claim_witness` at `deposits-core/src/tapscript_reserves.rs:1421` produces this witness exactly. The script consumes each preimage in order, hashes it against the committed hash, accumulates the contribution on the altstack, sums to get `total`, computes `total mod N`, dispatches to the matching pubkey, and verifies the signature. If any preimage is wrong, any contribution is out of range, or the signer's pubkey isn't `pubkey_(sum mod N)`, the script fails and the spend is rejected. There is no off-chain agreement on who won — the script is the arbiter.

For partial-reveal leaves, the layout is identical except only N−1 preimages are pushed (the missing disputant's slot is skipped) and the spending input must have `nSequence ≥ 72` to satisfy the leaf's CSV prefix.

After the claim transaction confirms, the winner publishes `DisputeAcquire { new_custodian, claim_txid, new_reserves_address }` on their fork-branch of the disputed ledger. Losing disputants publish `DisputeYield`. The fork-branch with `DisputeAcquire` becomes the canonical continuation of the ledger; its operator is now the winner. See [Chapter 12](12-recovery-pipeline.md) for the full pipeline including how the new operator inherits the deposit obligations.

Two distinct confiscation modes worth calling out:

- **Respectful custody** (operator unavailable but not provably dishonest): only the value covering open obligations goes to the lottery; change goes back to the original operator's pubkey via the optional output 1 above. Collateral isn't touched. The operator can still pay creditors with whatever they've got left.
- **Punitive custody** (proven non-conformance): the *entire* UTXO — reserves and collateral — goes to the lottery output. The winner inherits deposit obligations; the collateral is forfeited to the winner as compensation for taking on the work. Excess reserves above obligations get split equally among quorum members. This is the slashing path that makes the protocol's economics work.

## Cooperative on-chain exit

The cooperative path: a depositor wants to leave the ledger and withdraw to a mainchain address. They send the operator a withdrawal request signed against their deposit's miniscript descriptor (`deposits-core/src/descriptor.rs::verify_witness`). The operator validates the signature, debits the deposit's balance with an `OnchainLock` operation (locking funds for an outgoing withdrawal — `LedgerOperation::OnchainLock` at `deposits-protocol/src/messages/types.rs:289`), gets it cosigned by the quorum, then constructs a transaction:

```
INPUT:                                       OUTPUTS:
  current reserves UTXO                      [0] depositor's withdrawal address
  witness: Tier 0 — majority quorum sig          value = locked withdrawal amount
                                             [1] new reserves UTXO (P2TR, refreshed
                                                 ledger_hash, smaller value)
                                             [2] OP_RETURN <chain_hash> (optional)
```

The depositor's output pays them exactly what they locked (minus on-chain fees, which `OnchainLock` records up front in `fee_sats`). The new reserves output is the full reserves UTXO minus the withdrawal — the rotation and the withdrawal happen in one transaction so the ledger doesn't briefly sit without an anchor.

When the transaction confirms, the operator publishes `OnchainFulfill` with the txid; the wallet sees the fulfillment and considers the funds settled. If the operator never broadcasts (or can't get cosigners to sign), the wallet escalates via the `delivery_embed` request mechanism (Chapter 15) and ultimately, if the operator continues to ignore them, can accumulate the evidence into a fraud proof. Withdrawal stalls are detectable.

The reverse direction — funding a deposit by sending Bitcoin *into* the ledger — does not require the operator to spend the reserves UTXO at all. The depositor sends to a per-deposit address controlled by a wallet-side key, the operator notices the confirmation through their watch-only view of that address, and credits the deposit with an `OnchainCredit` operation. The reserves UTXO grows only at rotation time, when the operator rolls the now-larger total into a new `QuorumBegin`. This is part of why on-chain activity is so light: incoming deposits do not move the reserves UTXO directly.

## Timeout fallbacks

Tier 1, 2, and 3 of the reserves tree are not optimization choices — they are existence guarantees that the funds are eventually recoverable even when most of the quorum disappears. Walking up the tree:

- **Tier 1 (minority quorum, ~1 week CSV).** If a few members are unresponsive but a minority are still around, the minority can rotate after one week. This handles "members on vacation" without involving the operator.
- **Tier 2 (operator-solo, ~2 week CSV).** If the operator has lost essentially the entire quorum, they can move the funds alone after two weeks. The operator must still honor deposit obligations off-chain (the ledger continues to exist), but at least the funds aren't permanently frozen behind absent cosigners. Two weeks is a long enough wait that, if the operator is the misbehaving party, the quorum has plenty of time to detect, dispute, and confiscate first via Tier 0.
- **Tier 3 (anyone, ~4 week CSV).** If nobody from the quorum and not even the operator is reachable — a true catastrophic abandonment scenario — anyone holding any of the relevant keys can sweep after four weeks. This is the absolute last resort, and the four-week wait is long enough that any honest party has had plenty of opportunity to act through earlier tiers.

Each tier is a separate Taproot leaf, so spending through any one of them reveals only that leaf's script in the witness. The tradeoff is direct: longer dispute window = more time for cooperative paths to succeed = less risk of incorrect confiscation, but also = longer worst-case time before funds are recoverable. The reference timelocks (1008 / 2016 / 4032) are tuned for operator-grade availability expectations; deployments serving more ad-hoc operators might lengthen them, deployments with high-uptime operators might shorten Tier 1.

The same long-tail-cascade pattern shows up on the lottery output (CSV 144 / 1008 / 4032 with descending thresholds), and for the same reason. Recovery quorums can be partially absent during a dispute too, and the lottery output must be sweepable somehow.

## A worked example

Consider a Q=4 ledger (operator A; quorum members B, C, D, E — four cosigners). A typical reserves rotation looks like this:

```
Inputs (1):
  outpoint = a3f2...:0   (current reserves UTXO, value = 0.50000000 BTC)

Outputs (2):
  [0] P2TR a91e...     (new reserves UTXO, value = 0.49998500 BTC)
  [1] OP_RETURN <chain_hash_of_QuorumBegin_at_seq_138>   (32 bytes)

Witness on input 0 (Tier 0 leaf, threshold = 3-of-4 cosigners):
  [empty]                  (unused signature slot for B)
  <sig_C>
  <sig_D>
  <sig_E>
  <leaf_0_script>          (the Tier-0 CHECKSIGADD script)
  <control_block>          (proves leaf_0 is in the merkle tree)

Signers:
  C, D, E   (three of four cosigners; B was offline this round)
  Operator A: NOT a signer of this transaction — the operator is excluded from Tier 0.
```

Total on-chain footprint: ~210 vbytes. At 5 sat/vbyte, the rotation costs about 1500 sats (deducted from the UTXO's collateral portion by accounting). The operator broadcasts; after one regtest confirmation (or six on mainnet), publishes `QuorumBegin` with the new outpoint. B catches up by replaying the relay, sees the new UTXO, and can cosign the next ledger update normally. The whole cycle is on the order of one block plus a handful of seconds for off-chain coordination.

The same UTXO during a confiscation looks completely different. Suppose A misbehaves and B and C dispute. The recovery quorum is {D, E} plus whatever other peers signed up as recovery voters; both B and C participate as disputants but not as confiscation-tx signers. The confiscation tx spends the original reserves UTXO into a 2-disputant lottery output (Regime A linear dispatch, since N=2). After both disputants reveal, the winner — say B — broadcasts a claim transaction whose witness is `[sig_B, preimage_C, preimage_B, leaf_0_script, control_block]`. The script verifies both hashes, computes `sum mod 2`, sees that the result is 0 (which routes to B's pubkey), and accepts B's signature. B is now the operator of the ledger, with the lottery value sitting in their newly-funded reserves UTXO. A's collateral is gone — confiscated to B as compensation. C posts `DisputeYield`; B posts `DisputeAcquire`; their fork-branch of the ledger becomes the canonical continuation. Three transactions total: rotation, confiscation, claim — and that's the entire on-chain footprint of the dispute, regardless of how many deposits were on the ledger.

## What stays in your head

- A ledger has one P2TR UTXO. It holds reserves + collateral, both portions audited by the same quorum. The internal key is NUMS — no key-path spend, ever.
- The script tree has tiers: cooperative-quorum (Tier 0, immediate), degraded-quorum (Tier 1, ~1 week), operator-solo (Tier 2, ~2 weeks), emergency-anyone (Tier 3, ~4 weeks). The operator is excluded from Tier 0 and Tier 1 — those exist for the quorum to act *without* the operator.
- The ledger hash is committed into an unspendable leaf. Wallets can verify the on-chain `scriptPubKey` matches the off-chain `QuorumBegin` without trusting any relay.
- Routine on-chain activity is just rotations: one P2TR-to-P2TR spend per quorum-membership change or expiry deadline, plus an `OP_RETURN` checkpoint.
- Disputes spend the UTXO into a lottery Taproot output whose tapscript tree determines the winner from disputant-supplied preimages. The script is the arbiter; no off-chain agreement on outcome is needed.
- Cooperative on-chain exits combine the depositor's payout with a reserves rotation in a single transaction, so the ledger never sits without a UTXO anchor.

## Where this leads

[Chapter 6](06-peer-messaging.md) leaves the chain and looks at the off-chain transport: what events get broadcast on Nostr, how cosignatures are collected, how wallets and operators talk to each other above the transaction layer. The on-chain transactions in this chapter are infrequent, expensive, and load-bearing; the off-chain messages are continuous, cheap, and where the bulk of the protocol's daily work actually happens.
