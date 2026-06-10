# DEP-06: Fraud Proofs and Recovery

## Abstract

This document specifies fraud proof construction, embedding, broadcast, and verification, as well as the dispute and recovery protocol.

## Fraud Proof Types

1. **Uncredited on-chain payment**: operator saw sufficient confirmations (proved by block_height in signed updates) but did not credit the deposit. Wallet constructs this autonomously.

2. **Uncredited lightning payment**: operator created a cosigned invoice, received payment (proved by preimage), but did not credit the deposit. Requires the payer to provide the preimage to the wallet.

3. **Stale co-signature**: a co-signer's `member_ledger_hash` in a signed update precedes their own later hash — proving they backdated their attestation.

4. **Inactive quorum member**: a member was active (their ledger has updates after the fraud) but did not initiate a dispute within the required block window.

5. **Non-conforming update**: the operator signed a ledger update that violates protocol rules (e.g., spending more than balance, invalid fee collection).

6. **Winner collateral deviation**: the lottery winner's broadcast claim TX deviates from the replacement collateral they committed to in `DisputeArmed` — missing the second input, pointing at a different UTXO, committing less than declared, or adding change outputs that drain the pledged amount. Verifiable on-chain by inspecting the claim TX against the disputant's stored `DisputeArmed` declaration.

## Proof Construction

A fraud proof is a hashable evidence document:

    tag = SHA256("deposits/fraud_proof")
    proof_hash = SHA256(tag || tag || proof_type_byte || accused_pubkey || ledger_id || evidence_bytes)

The `evidence_bytes` are canonical and vary by proof type.

## Embedding

The 32-byte `proof_hash` is embedded into a ledger chain as wallet-controlled data — typically as the `nonce` field (type 210) in a self-transfer (see DEP-09). Once the operator signs an update containing this hash, the evidence is causally ordered.

Embedding targets (in order of preference):
- **Direct**: on the accused operator's ledger
- **One hop**: on a quorum member's ledger, entangled at next co-signature
- **Further**: any ledger in the web, waiting for causal propagation

## Broadcast

A fraud broadcast (Kind 9101 Nostr event) contains:

- **proof**: the hashable evidence (proof type, accused, ledger_id, evidence)
- **embedding**: where the hash was placed (ledger_id, sequence, update_hash, field name)
- **causal_chain**: ordered list of co-signed updates linking the embedding to the accused ledger

Each `CausalLink` is a co-signed update on ledger X whose `member_ledger_hash` comes from ledger Y, proving X happened after Y.

Direct embedding: empty chain. One hop: one link. Longer paths: multiple links.

## Verification

A verifier:

1. Hashes the proof, confirms it matches the nonce at `embedding.sequence`
2. Walks the causal chain: each link's `source_ledger_id` matches the previous link's `ledger_id`
3. Confirms the last link reaches the accused ledger
4. Fetches and verifies signatures on each referenced update

## On-chain vs Lightning Evidence

**On-chain** (autonomous): the wallet has all evidence — cosigned offer, block height proving confirmations, absence of credit on the ledger. The fraud proof is constructed and embedded without interaction.

**Lightning** (interactive): the wallet has the cosigned invoice but NOT the preimage. The payer must provide the preimage (their receipt of payment). Only then can the wallet verify `SHA256(preimage) == payment_hash` and construct the proof. Without the preimage, the wallet can only flag the invoice as outstanding.

## Dispute Lifecycle

### Enter (disc 54)

When a quorum member detects fraud (via Kind 9101 broadcast or direct observation), they:

1. Create a fork of the disputed ledger from the last valid sequence
2. Append `DisputeEnter` with the reason and last valid sequence
3. Append `DisputeArmed` with a commitment hash (HASH160 of a secret preimage) and target reserves address

### Lottery

The lottery determines which quorum member takes custody of the disputed ledger. Selection happens *on chain*, enforced by a Tapscript that only lets the script-determined winner spend the lottery output. Off-chain agreement on the outcome is not required. See DEP-03 §"Custody Lottery" and `CUSTODY_LOTTERY.md` for full script construction details.

#### Phase 1: Commitment (DisputeArmed)

Each participating quorum member appends `DisputeArmed` to their fork with:

- **commitment_hash**: `HASH160(preimage)` where `preimage` is a 17-to-`(16+N)`-byte random value chosen by the member. The preimage's *length* contributes the entropy: `contribution = LEN(preimage) - 16` lies in `1..=N`.
- **target_reserves**: the bitcoin address where the member wants their winnings sent if they win
- **armed_block**: the block height at time of arming
- **replacement_collateral_outpoint**: txid + vout of an unspent UTXO the disputant controls and pledges to commit to the new vault if they win (see DEP-03 §"Replacement collateral declaration")
- **replacement_collateral_amount**: the value (in sats) they pledge to commit from that UTXO; must satisfy `≥ obligations × collateral_ratio + claim_fee_estimate` where `obligations` is the total deposits owed at `last_valid_sequence`

Members must arm within `dispute_arm_blocks` after `DisputeEnter`. Late entries are excluded. `dispute_arm_blocks` is recorded in `QuorumAddMember` so all parties agree on the obligation at join time.

The participant ordering (canonical, derived from sorted `quorum_pubkey`) and the committed hashes go into the lottery script that the confiscation transaction will lock funds into.

#### Phase 2: Confiscation

After the arm window closes, the recovery quorum (quorum members minus the disputants — the disputed operator + non-arming members) cosigns a confiscation transaction that spends the disputed reserves UTXO to a new Taproot output: the **lottery output**. The required recovery-quorum threshold for the confiscation cosignature follows the lifecycle schedule in DEP-05 §Lifecycle: a strict majority of the recovery quorum at Tier 0 (immediately past `quorum_expiry`), a minority at Tier 1 (`quorum_expiry + 720`), a single recovery-quorum member at Tier 2 (`quorum_expiry + 4032`). The confiscation transaction's on-chain spend witness uses the matching on-chain tier from DEP-03 §Spending Tiers, so on-chain and off-chain authority always agree at the chain tip when the confiscation TX is signed.

Its tapscript tree contains:

- A primary lottery claim leaf that dispatches to the `(sum mod N)`-th disputant on full reveal
- For N≥3, K=1 partial-reveal leaves at CSV 72 (one per missing disputant) that handle the dominant single-non-revealer case
- A long-tail recovery cascade at CSV 144 / 1008 / 4032 with thresholds T / T-1 / T-2
- A timeout-recovery escape hatch at CSV 8064 with threshold 1

#### Phase 3: Reveal (CustodyLotteryReveal)

Once the confiscation transaction confirms, each disputant publishes a `CustodyLotteryReveal` event (Nostr Kind 9106) carrying their preimage. The signature on the reveal binds `(ledger_id, preimage)` to the disputant's identity.

#### Phase 4: Claim and Settlement (DisputeAcquire)

The script's selection rule: **winner index = sum(LEN(preimage_i) - 16) mod N**, where preimages are ordered by sorted disputant pubkey. Only the winner's signature satisfies the lottery claim leaf, so Bitcoin itself enforces the outcome.

The winner:

1. Collects all revealed preimages from Nostr
2. Computes the winning index off-chain via `LotteryOutput::calculate_winner` (must agree with what the script will accept)
3. Constructs the claim transaction spending the lottery output to their `target_reserves` (see DEP-03 for witness construction)
4. Broadcasts the claim TX
5. Appends `DisputeAcquire` to their fork carrying `claim_txid` (the claim TX's hash), `new_custodian`, and `new_reserves_address`
6. Establishes a new quorum on the ledger and begins co-signing updates as the new operator

Losers append `DisputeYield` to their forks, transitioning them to Tombstoned state. Only the winner's fork continues as the canonical ledger.

If exactly one disputant fails to reveal within the timeout, the remaining N-1 can spend through the partial-reveal leaf for that missing index — same lottery mechanics, just over the smaller revealer set. If 2+ fail to reveal, the dispute falls through to the CSV-144 recovery cascade.

#### Pre-release policy cap

The script supports up to N=15 disputants, but the operational policy in this release is `VALID_QUORUM_SIZES = {3, 5, 7}` with `MAX_QUORUM_SIZE_POLICY = 7` (`Q` is the cosigner count and excludes the operator) → at most 7 disputants per dispute. The operator is barred from disputing their own ledger by `validate_update_signer` and was never counted in `Q`, so disputants equal `Q` exactly. `Ledger::validate_operation` rejects `QuorumBegin` whose `Q` falls outside the allowed set. Lifting the cap or extending the set is a one-line constant change with no script or wire-format implications.

#### Respectful vs Punitive

**Respectful** (unavailability without proven fraud, `QuorumExpired`):
- Only the amount covering the ledger's obligations goes to the winner
- Change (including collateral) is returned to the original operator's pubkey
- Past `quorum_expiry`, this path races against the operator's own
  re-establishment under the same lifecycle tiers — see §Race below
  and DEP-05 §Lifecycle. The recovery-quorum cosignature threshold
  for the confiscation TX cascades through the same tiers, so a
  minority of cosigners can drive a respectful confiscation at
  Tier 1, a single cosigner at Tier 2.

**Punitive** (proven non-conformance):
- The amount covering the ledger's obligations goes to the lottery output (the winner inherits those obligations against that backing)
- The remainder (excess reserves + full collateral) is split equally across the **armers** (DisputeArmed participants), one per-armer slashing-share output. Non-armers get no slice — arming is the gate to a share, revealing is the gate to keeping it (see §"Arm-and-reveal forfeiture" below).
- If the operator runs multiple ledgers, proof of non-conformance on one ledger can be presented to the other ledgers' quorums, triggering slashing there as well
- Punitive disputes operate at strict majority; they do not cascade
  through the lifecycle tiers because the misbehaviour is provable
  *now* — the protocol does not wait for cosigners to vanish before
  acting on a non-conforming update.

##### Arm-and-reveal forfeiture

Each armer's slashing-share output is a P2TR with two tapscript leaves:

- **Reveal-claim** (`OP_HASH160 <commitment_hash> OP_EQUALVERIFY <armer_xonly> OP_CHECKSIG`): the armer spends by revealing the same preimage they committed to in their `DisputeArmed` plus a Schnorr signature. Spending this leaf publishes the preimage on-chain — if the armer somehow missed the Nostr reveal window, the on-chain spend doubles as a reveal that other observers can use.

- **Sweep** (`<ARMER_SHARE_SWEEP_CSV_BLOCKS> OP_CSV OP_DROP` + recovery-voter threshold CHECKSIGADD pattern): after `ARMER_SHARE_SWEEP_CSV_BLOCKS = 144` blocks (~1 day, matching the lottery's recovery long-tail floor), the recovery quorum (= quorum minus original operator) can sweep the slice as forfeited.

The internal key is the standard NUMS point so the key path is unspendable. The recovery_voters set for the sweep leaf matches the main lottery's recovery_voters — same set, same threshold — so the two outputs' sweep semantics are in lockstep. An armer remains in the recovery set that can sweep their own slice, but the threshold requires cooperation from other cosigners, which a non-revealing armer is unlikely to get.

The "abort option" — armer arms (so the dispute proceeds and the confiscation TX names them in the per-armer outputs), then withholds their reveal — now carries a real cost: their slice falls to the sweep after the CSV expires. See `tapscript_reserves::build_armer_share_output` for the implementation and the `armer_*` tests in `lottery_script_execution.rs` for the witness paths.

##### Sweep recipients: pro-rata to revealers

The sweep leaf permits the recovery quorum to spend the slice; the leaf does NOT constrain where the funds go (tapscript has no general output-commitment opcode). The protocol-defined contract for honest sweepers is:

> **The sweep TX MUST pay the slice (less fee) pro-rata to the set of revealers, split into one P2TR output per revealer keyed by `armer.pubkey`.**

A *revealer* is an armer whose preimage appears in the lottery output's claim TX witness OR in a published `CustodyLotteryReveal` event before the sweep TX is constructed. Equivalently: an armer who satisfied either the primary lottery leaf, a partial-reveal leaf, or signed a Kind 9106 reveal that the sweepers can verify against the on-chain `commitment_hash`. The set of revealers is derivable from public evidence (chain + relay) at sweep time; sweepers are expected to compute it deterministically and agree on the resulting recipient list before cosigning the sweep TX.

Math for a single sweep:
```
slice_value = <per-armer share from the confiscation TX>
fee         = <sweep TX fee estimate>
per_revealer = (slice_value - fee) / N_revealers
dust         = (slice_value - fee) - (per_revealer * N_revealers)   // absorbed as additional fee
```
Order recipients by sorted `armer.pubkey` so the constructed TX is deterministic and reproducible by every honest signer.

Edge case — `N_revealers == 0`: no one revealed at all (the lottery itself fell through to its recovery cascade). In that case the sweep TX has no honest recipient set; the recovery quorum may sweep the slice into a single output for whichever recovery destination they normally direct lottery-recovery funds to (typically the original operator's pubkey, mirroring the respectful-confiscation change output). This case is degenerate — if no one revealed, the whole lottery already failed — but the sweep path still needs SOME defined destination.

Honest-sweeper enforcement: a sweep TX whose outputs deviate from this pro-rata-to-revealers contract is publicly observable. Sweepers who construct a deviating TX are themselves cosigners of the same ledger, and the deviation is a form of provable misbehavior. A `MaliciousSweep` fraud-proof type may be added later; for now the contract is enforced by recovery-quorum honesty and the social/reputational cost of public deviation. This is no stronger an honesty assumption than the recovery-quorum already requires for the lottery's own recovery long-tail.

### Race: Re-establishment vs Confiscation

Past `quorum_expiry`, two paths compete for the same on-chain
reserves UTXO at every lifecycle tier (see DEP-05 §Lifecycle for the
full schedule):

- **Re-establishment** — the operator initiates a fresh `QuorumBegin`
  with whatever cosigners they can still reach, spending the reserves
  UTXO into a new vault. The off-chain cosignature threshold and the
  on-chain script-path threshold both come from the current tier.
- **Confiscation** — a sufficient quorum-member subset files a
  `QuorumExpired` dispute (respectful only — see §"Respectful vs
  Punitive" above), arms, and cosigns a confiscation TX. Same
  tier-keyed threshold on both layers.

Because both paths consume the same on-chain UTXO, the tiebreaker is
which spending transaction confirms on-chain first. The losing path's
TX, if broadcast at all, becomes a double-spend and is dropped from
mempools. Off-chain ledger state follows: the prevailing TX is either
the `new_outpoint` of a fresh `QuorumBegin` (re-establishment won) or
the input of a confiscation lottery output (confiscation won).
Wallets verifying ledger continuity reconcile against whichever
appears on-chain.

The cascade is not "first to act in a tier wins"; it is "first tier
opens, both options simultaneously become valid." At Tier 1
(`quorum_expiry + 720`), the operator and a minority of cosigners can
re-establish, AND a minority of cosigners can confiscate — the
on-chain UTXO contention resolves the race. The operator's incentive
to win is preserving reputation and other ledger commitments; the
cosigners' incentive to win is the slashing reward (punitive) or the
operator-fee takeover (respectful).

Tier 3 has no confiscation pair — only the operator can sign Tier 3
on-chain, so only re-establishment is available there. By the time
the chain tip reaches `quorum_expiry + 8064`, every cosigner-driven
path has been available for ~8 weeks; the choice is the operator's
reputation against the unconditional Tier-3 spend.

### Recovery

Wallets continue addressing the same ledger by its `ledger_id`, accepting only replies co-signed by the quorum. When co-signatures stop or fail verification, the wallet should:

1. Query the network for dispute events (Kind 9103) on the ledger
2. Replay ledger updates to identify the last valid sequence
3. Look for `DisputeAcquire` events to identify the new operator and the `claim_txid`
4. Wait for the lottery output's claim transaction to confirm on-chain and verify that the `DisputeAcquire`'s `claim_txid` matches a confirmed transaction that spends the expected lottery output (see DEP-03)
5. Verify the new operator's quorum and begin accepting their co-signed updates

Wallets must not accept post-dispute updates until the on-chain claim transaction is confirmed. The claim transaction's witness satisfies the lottery script's `(sum mod N)`-th-disputant rule, so Bitcoin itself proves the new custodian is the script-selected winner. This prevents an attacker from publishing fake `DisputeAcquire` events claiming custody before the lottery resolves.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DisputeEnter, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-03](DEP-03.md): On-chain transactions (lottery construction, respectful custody)
- [DEP-04](DEP-04.md): Peer messaging (Kind 9101 fraud proof, Kind 9103 dispute events)
- [DEP-05](DEP-05.md): Quorum and collateral (quorum members initiate disputes, collateral confiscation)
- [DEP-09](DEP-09.md): Transfers (nonce field used for proof embedding)
- [DEP-10](DEP-10.md): Payment channels (cosigned offers/invoices as evidence)
