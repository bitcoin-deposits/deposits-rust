# DEP-03: On-Chain Transactions

## Abstract

This document specifies the on-chain transaction formats used by Bitcoin Deposits: the reserves UTXO structure, tapscript multisig construction for quorum spending, reserves rotation transactions, and the lottery mechanism for contested custody transfers.

## Reserves UTXO

A ledger's funds are held in a single UTXO containing both reserves and collateral. The reserves portion (deposit capacity) must be greater than or equal to the ledger's total obligations. The collateral portion is the operator's security bond. The UTXO is spendable by tiered script paths — quorum members first, operator later, with increasing timelocks.

## Tapscript Construction

The reserves UTXO uses a Taproot output with a tapscript tree containing tiered spending paths. The internal key is an unspendable point (no key-path spend). All spending goes through script-path reveals.

### Spending Tiers

Each tier (other than the immediate quorum-majority path) is gated by an
absolute `OP_CLTV` timelock anchored to the ledger's recorded
`quorum_expiry`. The post-expiry cascade only opens once the quorum's
declared lifetime has elapsed; during the active period the only
on-chain spend path is the quorum-majority tier, which is what the
routine rotation TX uses. This means:

- The on-chain script's protection does **not** decay with UTXO age —
  it decays with `quorum_expiry`. Refreshing `quorum_expiry` (via a
  rotation that emits a new `QuorumBegin`) re-pins all post-expiry
  tiers to the new deadline.
- An operator who fails to rotate before `quorum_expiry` loses
  exclusive spending control on a fixed schedule, with the quorum
  members' recovery paths opening earlier than the operator's own.
- The operator's solo path is the absolute last resort, opening only
  after every quorum-driven path has had time to act.

For a quorum of n members:

| Tier | Signers | Timelock | Purpose |
|---|---|---|---|
| 0 | Majority of quorum (no operator) | None — anytime | Normal operations: rotation, co-signed settlements |
| 1 | Minority of quorum (no operator) | `quorum_expiry + 720` blocks (~5 days) | Degraded quorum recovery when members disappear |
| 2 | Single quorum member (no operator) | `quorum_expiry + 4032` blocks (~4 weeks) | Recovery when only one member remains active |
| 3 | Operator only | `quorum_expiry + 8064` blocks (~8 weeks) | Operator solo, last resort after all quorum paths failed |

The operator is deliberately excluded from Tiers 0–2 and only gets
Tier 3 after every quorum-driven path has been available for weeks.
Routine rotation flows through Tier 0 and so has no timelock — the
quorum-majority cosigns each rotation TX while the current quorum is
still active.

This on-chain tier schedule is mirrored off-chain by the cosignature
threshold for *establishment operations* (`QuorumAddMember`,
`QuorumRemoveMember`, `QuorumBegin`) — see DEP-05 §Lifecycle for the
full event table. The two layers share the same anchor and offsets, so
authority at the chain tip is identical whether you read it from the
tapscript leaves or from the off-chain cosign rule. Non-establishment
operations remain strictly Tier-0 cosignable and become uncosignable
past `quorum_expiry` until a fresh `QuorumBegin` resets the schedule.

For the simple 2-party case (n ≤ 2), the minority and single-member
tiers collapse (in a 2-of-2 quorum, one member IS both), so the
cascade is:

| Tier | Signers | Timelock |
|---|---|---|
| 0 | Both quorum members | None — anytime |
| 1 | Single quorum member | `quorum_expiry + 720` blocks (~5 days) |
| 2 | Operator only | `quorum_expiry + 8064` blocks (~8 weeks) |

Block heights are absolute, encoded as `OP_CLTV` (BIP-65) against
`nLockTime`. Spending a non-zero-tier path requires the spending TX
to set `nLockTime ≥ quorum_expiry + offset`.

## QuorumBegin (disc 12)

When a quorum is established or refreshed, the operator constructs a new Taproot output and broadcasts a transaction spending the old reserves to the new address. The `QuorumBegin` operation records:

- **reserves_id**: the new Taproot address
- **reserves_amount**: the reserves portion of the UTXO (deposit capacity, msats)
- **collateral_amount**: the collateral portion of the UTXO (security bond, msats)
- **spending_txid**: the txid spending the old reserves
- **new_outpoint_txid**: the txid of the new reserves output
- **new_outpoint_vout**: the vout index
- **quorum_members**: the pubkeys included in the new multisig. MUST match the set of members staged via prior `QuorumAddMember` operations (and not since removed by `QuorumRemoveMember`) — `QuorumBegin` promotes exactly that staged set to the new active quorum (see DEP-05 §QuorumBegin).
- **quorum_member_ledger_ids**: parallel array to `quorum_members` carrying each member's own ledger_id (the ledger holding their collateral, sourced from the matching `QuorumAddMember.member_ledger_id`). Lets fraud-proof verifiers and explorers identify the ledger backing each cosigner's `member_ledger_hash` without re-deriving the mapping from prior `QuorumAddMember` history. Older `QuorumBegin` events omit this field; consumers fall back to walking `QuorumAddMember` operations on the operator's ledger.
- **quorum_expiry**: block height when the quorum expires (shortest member commitment)

The on-chain UTXO value MUST equal `reserves_amount + collateral_amount`. Cosigners MUST verify, against their own chain source, that the referenced outpoint (`new_outpoint_txid`, `new_outpoint_vout`):

1. exists on-chain,
2. is unspent,
3. carries a value (in sats) equal to `(reserves_amount + collateral_amount) / 1000`,
4. has at least a network-dependent minimum number of confirmations.

The per-network default confirmation thresholds used by an honest cosigner with no explicit override are: 6 for mainnet, 3 for testnet/signet, 1 for regtest. These are policy (not consensus) — a stricter cosigner is free to refuse a request a laxer cosigner would accept. A cosigner receiving a first `QuorumBegin` that fails any of the checks above MUST refuse to sign and MAY emit a diagnostic error; the operator's cosign collector then waits for another responder or times out.

After `QuorumBegin`, co-signatures become required for all subsequent updates. The *first* `QuorumBegin` itself must also carry cosignatures — see DEP-05 §QuorumBegin and DEP-02 §Cosignatures. A new `QuorumBegin` MUST be appended before `quorum_expiry` (see DEP-11).

### On-Chain State Anchor

The reserves rotation transaction should include an `OP_RETURN` output containing the `chain_hash` at the `QuorumBegin` sequence. This gives wallets an on-chain anchor to verify that the ledger state on relays matches the operator's committed state at the time of rotation — without trusting any relay. The `OP_RETURN` output is:

    OP_RETURN <chain_hash (32 bytes)>

This is cheap (one additional output on a transaction the operator is already making) and provides a verifiable checkpoint for wallets that suspect relay censorship or data loss.

## Custody Lottery

When a ledger becomes contested (dispute), quorum members compete for custody via an on-chain Tapscript lottery. Selection is enforced by Bitcoin script — the (sum mod N)-th disputant in canonical order is the only one whose signature satisfies the claim leaf. Off-chain agreement on the outcome is not required.

### Flow

1. Each disputing member publishes `DisputeArmed` with a `commitment_hash = HASH160(preimage)` where `preimage` is a 17-to-`(16+N)`-byte random value. The preimage's *length* contributes the entropy: `contribution = LEN(preimage) - 16` lies in `1..=N`.
2. After the arm window closes, the recovery quorum cosigns a confiscation transaction spending the disputed reserves UTXO into a new Taproot output: the **lottery output**.
3. Each disputant publishes their preimage as a `CustodyLotteryReveal` event (Nostr Kind 9106).
4. Once all reveals are observed, the script-determined winner = `(sum_of_contributions) mod N` constructs and broadcasts the **claim transaction**, providing all preimages and their signature in the witness.
5. The winner appends `DisputeAcquire { new_custodian, claim_txid, new_reserves_address }` to their fork. Losers append `DisputeYield`.

### Lottery Output Tapscript Tree

The lottery output's tapscript tree contains:

- **Leaf 0 — Primary lottery claim.** Verifies all N preimages, enforces per-preimage size bounds (`17 <= LEN(preimage_i) <= 16+N` via `OP_SIZE OP_DUP <17> OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP <16+N> OP_LESSTHANOREQUAL OP_VERIFY` immediately after each `OP_EQUALVERIFY`), computes `sum mod N`, dispatches to the matching pubkey via `OP_CHECKSIG`. The size bounds reject a committer who hashed an out-of-range preimage — without them, a malicious committer could reveal a preimage of any length, the hash check would pass (it matches what they committed to), and `contribution = LEN - 16` would take an arbitrary value that shifts `sum mod N` and corrupts the draw for the entire quorum. Three dispatch regimes by N:
  - **Linear** (N=2..=5 and N=11..=15): repeated conditional subtraction for `sum mod N`, then linear `if/elif` cascade on the index
  - **CombinedTable** (N=6..=10): skip the modulo; emit one dispatch arm per integer sum value in `[N, N²]` directly routing to `pubkey_(s mod N)`
- **Leaves 1..=N** (for N≥3): K=1 partial-reveal claim leaves, one per missing-disputant index, prefixed with `OP_PUSHNUM_72 OP_CSV OP_DROP`. Each is a sub-lottery for the (N-1) revealers excluding that index, picking its own dispatch regime by N-1. The per-preimage size bounds inside each sub-leaf use the *parent* N (`17..=16+N`), not `N-1` — surviving disputants committed under the parent contract and their valid preimages may legitimately extend to length `16+N`. The floor is `N=3` because the sub-lottery needs at least 2 participants; at `N=2` a single non-revealer leaves only one possible spender, making "lottery" degenerate.
- **Long-tail recovery cascade**: `<csv> OP_CSV OP_DROP <threshold> <pubkeys> OP_CHECKMULTISIG` at CSV 144 / 1008 / 4032 with descending thresholds T / T-1 / T-2 (where T is the recovery threshold computed at confiscation time).
- **Timeout-recovery escape hatch**: CSV 8064 (~8 weeks) with threshold 1 — any single recovery voter can sweep if all else has failed.

The internal key is the BIP-341 NUMS point (no key-path spend possible).

### Witness Construction

For the primary claim leaf, the witness is:

    [signature, preimage_{N-1}, ..., preimage_0, leaf_script, control_block]

with the signature at the bottom of the stack. The script consumes preimages in disputant order, accumulates contributions on the altstack, computes the dispatch index, and verifies the signer's pubkey matches `pubkey_(sum mod N)`.

For partial-reveal leaves (N≥3): identical layout, but only the `N-1` revealer preimages, and the spending input must have `nSequence >= 72`.

For recovery leaves: standard tapscript multisig — `K` of `N` signature slots filled (with empty pushes for unused slots), and `nSequence >= csv_blocks`.

### Pre-release policy cap

The script supports up to N=15 disputants. The current policy in this release is `VALID_QUORUM_SIZES = {3, 5, 7}` with `MAX_QUORUM_SIZE_POLICY = 7`, enforced at `QuorumBegin` validation. `Q` is the cosigner count and excludes the operator; disputants equal `Q` exactly (every cosigner can dispute, the operator is barred from disputing their own ledger). Lifting the cap or extending the allowed set is a one-line constant change with no script or wire-format implications. See `CUSTODY_LOTTERY.md` for full design rationale.

### Fraud-proof classification: Respectful vs Punitive

Every dispute is initiated by a fraud proof — quorum members don't dispute on
"vibes." The proof's *type* determines whether the dispute is respectful or
punitive, which in turn shapes both the confiscation tx and cross-ledger
propagation:

| Fraud proof type      | Class       | Trigger condition                                                                  |
|-----------------------|-------------|------------------------------------------------------------------------------------|
| `QuorumExpired`       | Respectful  | Operator failed to rotate before `quorum_expiry`                                   |
| `UncreditedOnchainPayment` | Punitive   | Operator received on-chain payment, didn't credit despite signing past confs       |
| `UncreditedLightningPayment` | Punitive | Operator received Lightning payment, didn't credit despite preimage release        |
| `StaleCosignature`    | Punitive    | Cosigner backdated their `member_ledger_hash` (signed against an outdated state)   |
| `DisputeDereliction`  | Punitive    | Cosigner was online but failed to act on a prior fraud proof within the window     |
| `NonConformingUpdate` | Punitive    | Operator signed a ledger update that violates protocol rules                       |
| `WinnerCollateralDeviation` | Punitive | Lottery winner's broadcast claim TX deviates from their `DisputeArmed` collateral declaration (missing input, smaller commit, or extra drain) |

### Respectful custody (QuorumExpired only)

When the operator fails to rotate before `quorum_expiry`, respectful
custody transfer becomes available — but it now races against the
operator's own re-establishment path under the same lifecycle tiers
(see DEP-05 §Lifecycle and DEP-06 §"Race: Re-establishment vs
Confiscation"). If the operator self-rescues first with a degraded
`QuorumBegin`, no custody transfer occurs.

- The fraud proof is `QuorumExpired`. Evidence is just an anchor block hash
  whose height in the verifier's chain exceeds the ledger's `quorum_expiry`.
- Cosigners enforce the deadline at the cosign edge: past `quorum_expiry`,
  they refuse to cosign *value-moving* operations. They WILL still cosign
  *establishment* operations (`QuorumAddMember`, `QuorumRemoveMember`,
  `QuorumBegin`) at the threshold required for the current lifecycle
  tier — see DEP-05 §Lifecycle. Missing `quorum_expiry` is therefore
  not fatal; it opens both the confiscation path (this section) and
  the operator's degraded re-establishment path concurrently.
- Confiscation tx is bifurcated:
  - `obligations` worth of reserves → lottery winner
  - `(reserves − obligations) + full collateral` → operator's pubkey (change)
- The fraud proof does **not** propagate cross-ledger. Other ledgers the
  operator runs are unaffected.

### Punitive custody (proven non-conformance)

When proof of provable misbehaviour is presented:

- The full UTXO (reserves + collateral) goes to the confiscation tx.
  - `obligations` worth of reserves → lottery winner (becomes the new
    backing for inherited deposits).
  - The remainder, `(reserves − obligations) + collateral`, is split equally
    among the `Q` cosigners. **The lottery winner does not retain the
    confiscated collateral as a windfall** — they receive their per-cosigner
    share alongside everyone else, evenly aligning incentives across the
    quorum.
- The lottery winner takes over the ledger, inheriting deposit obligations
  and the lottery output.
- **The winner provides replacement collateral** as a fresh input when
  claiming the lottery output. The replacement amount + the inherited
  `obligations` reserves form the new operating UTXO. Operating a ledger
  is a service commitment, not a windfall; the winner pays the cost of
  fresh collateral to take the role.
- The same fraud proof can be presented to the operator's *other* quorums,
  triggering punitive disputes there as well. Cross-ledger contagion is
  the protocol's mechanism for ensuring an operator with multiple ledgers
  can't insulate one from misbehaviour on another.

### Replacement collateral declaration

Operating a ledger requires backing reserves with a collateral ratio `r`
(see DEP-05). The lottery output by itself only covers the inherited
`obligations` — it does not carry the collateral-ratio padding. To take
custody, the winner must commit *fresh collateral* alongside the lottery
output when constructing the claim transaction.

For both respectful and punitive disputes, every disputant MUST declare
in `DisputeArmed` a **replacement collateral UTXO** they would commit if
they win:

- `replacement_collateral_outpoint`: txid + vout of an unspent UTXO they
  control
- `replacement_collateral_amount`: the value (in sats) they pledge to the
  new vault from that UTXO

At confiscation cosign time, every cosigner verifies, against their own
chain source, that each disputant's declaration satisfies all of:

1. The outpoint exists on-chain and is unspent at the cosigner's tip
2. Its value is ≥ `replacement_collateral_amount`
3. The post-takeover collateralization inequality holds:

   ```
   replacement_collateral_amount  ≥  obligations × collateral_ratio + claim_fee_estimate
   ```

   where `obligations` is the total deposit value owed at
   `last_valid_sequence` (the lottery output covers exactly this amount,
   so only the ratio padding and fee need to come from the replacement).

If any disputant's declaration fails any check, the cosigner MUST refuse
to sign the confiscation transaction. The dispute is then stalled until
the failing disputant amends `DisputeArmed` (re-arming with a sufficient
UTXO before the arm window closes) or is excluded for missing the window.

The fee estimate floor is policy. Recommended default: 200 sat/vB ×
estimated multi-input claim TX vsize. A stricter cosigner is free to
refuse what laxer cosigners would accept.

### Claim transaction (multi-input)

The winner's claim TX has two inputs and one output:

- **Input 0**: lottery output (script-path spend through the primary or
  partial-reveal leaf — see §"Witness Construction")
- **Input 1**: the disputant's declared replacement collateral UTXO,
  signed natively for whatever script controls it (typically wpkh from
  the disputant's wallet)
- **Output 0**: the new reserves vault at the winner's `target_reserves`
  address, valued at `(input_sum − fee)`

If the winner broadcasts a claim TX whose shape deviates from their
declared commitment — single-input (skipping the replacement), pointing
at a different replacement UTXO, committing a smaller amount than
declared, or adding change outputs that drain replacement value — the
deviation is observable on-chain by comparing the broadcast TX against
the stored `DisputeArmed`. This deviation is a `WinnerCollateralDeviation`
fraud proof: punitive, attributed to the winner's new operator pubkey on
whatever ledger they're operating after takeover. Cross-ledger contagion
applies as for any other punitive proof.

Because Bitcoin script can't gate cross-input requirements atomically,
the constraint is enforced at two edges: cosigner-attested arm-time
verification (refuse to sign confiscation if the declaration is
insufficient) and after-the-fact fraud proof (slash the winner if they
broadcast a non-conforming claim).

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumBegin, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-05](DEP-05.md): Quorum membership determines multisig participants
- [DEP-06](DEP-06.md): Dispute lifecycle triggers the lottery
