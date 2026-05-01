# DEP-03: On-Chain Transactions

## Abstract

This document specifies the on-chain transaction formats used by Bitcoin Deposits: the reserves UTXO structure, tapscript multisig construction for quorum spending, reserves rotation transactions, and the lottery mechanism for contested custody transfers.

## Reserves UTXO

A ledger's funds are held in a single UTXO containing both reserves and collateral. The reserves portion (deposit capacity) must be greater than or equal to the ledger's total obligations. The collateral portion is the operator's security bond. The UTXO is spendable by tiered script paths — quorum members first, operator later, with increasing timelocks.

## Tapscript Construction

The reserves UTXO uses a Taproot output with a tapscript tree containing tiered spending paths. The internal key is an unspendable point (no key-path spend). All spending goes through script-path reveals.

### Spending Tiers

For a quorum of n members:

| Tier | Signers | Timelock | Purpose |
|---|---|---|---|
| 0 | Majority of quorum (no operator) | Immediate | Normal operations: rotation, co-signed settlements |
| 1 | Minority of quorum (no operator) | 1008 blocks (~1 week) | Degraded quorum recovery when members disappear |
| 2 | Operator only | 2016 blocks (~2 weeks) | Operator solo when quorum is unresponsive |
| 3 | Any single party | 4032 blocks (~4 weeks) | Emergency last resort recovery |

The operator is deliberately excluded from Tier 0 and 1. The quorum can operate and recover reserves without operator participation. The operator's solo spending path (Tier 2) is only available after a significant timelock, ensuring the quorum has ample opportunity to act first.

For the simple 2-party case (n ≤ 2):

| Tier | Signers | Timelock |
|---|---|---|
| 0 | Both quorum members | Immediate |
| 1 | Operator only | 2016 blocks |
| 2 | Any single party | 4032 blocks |

## QuorumBegin (disc 12)

When a quorum is established or refreshed, the operator constructs a new Taproot output and broadcasts a transaction spending the old reserves to the new address. The `QuorumBegin` operation records:

- **reserves_id**: the new Taproot address
- **reserves_amount**: the reserves portion of the UTXO (deposit capacity, msats)
- **collateral_amount**: the collateral portion of the UTXO (security bond, msats)
- **spending_txid**: the txid spending the old reserves
- **new_outpoint_txid**: the txid of the new reserves output
- **new_outpoint_vout**: the vout index
- **quorum_members**: the pubkeys included in the new multisig. MUST match the set of members staged via prior `QuorumAddMember` operations (and not since removed by `QuorumRemoveMember`) — `QuorumBegin` promotes exactly that staged set to the new active quorum (see DEP-05 §QuorumBegin).
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

- **Leaf 0 — Primary lottery claim.** Verifies all N preimages, computes `sum mod N`, dispatches to the matching pubkey via `OP_CHECKSIG`. Three dispatch regimes by N:
  - **Linear** (N=2..=5 and N=11..=15): repeated conditional subtraction for `sum mod N`, then linear `if/elif` cascade on the index
  - **CombinedTable** (N=6..=10): skip the modulo; emit one dispatch arm per integer sum value in `[N, N²]` directly routing to `pubkey_(s mod N)`
- **Leaves 1..=N** (only for N≥11): K=1 partial-reveal claim leaves, one per missing-disputant index, prefixed with `OP_PUSHNUM_72 OP_CSV OP_DROP`. Each is a sub-lottery for the (N-1) revealers excluding that index, picking its own dispatch regime by N-1.
- **Long-tail recovery cascade**: `<csv> OP_CSV OP_DROP <threshold> <pubkeys> OP_CHECKMULTISIG` at CSV 144 / 1008 / 4032 with descending thresholds T / T-1 / T-2 (where T is the recovery threshold computed at confiscation time).
- **Timeout-recovery escape hatch**: CSV 8064 (~8 weeks) with threshold 1 — any single recovery voter can sweep if all else has failed.

The internal key is the BIP-341 NUMS point (no key-path spend possible).

### Witness Construction

For the primary claim leaf, the witness is:

    [signature, preimage_{N-1}, ..., preimage_0, leaf_script, control_block]

with the signature at the bottom of the stack. The script consumes preimages in disputant order, accumulates contributions on the altstack, computes the dispatch index, and verifies the signer's pubkey matches `pubkey_(sum mod N)`.

For partial-reveal leaves (N≥11): identical layout, but only the `N-1` revealer preimages, and the spending input must have `nSequence >= 72`.

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

### Respectful custody (QuorumExpired only)

When the operator fails to rotate before `quorum_expiry`, the custody transfer
is *respectful*:

- The fraud proof is `QuorumExpired`. Evidence is just an anchor block hash
  whose height in the verifier's chain exceeds the ledger's `quorum_expiry`.
- Cosigners enforce the deadline at the cosign edge: past `quorum_expiry`,
  they refuse to cosign *any* operation, including a fresh `QuorumBegin`.
  The operator must rotate *before* the deadline; missing it is fatal to the
  current quorum.
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

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumBegin, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-05](DEP-05.md): Quorum membership determines multisig participants
- [DEP-06](DEP-06.md): Dispute lifecycle triggers the lottery
