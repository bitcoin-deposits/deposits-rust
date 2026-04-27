# DEP-05: Quorum and Collateral

## Abstract

This document specifies the quorum membership protocol and collateral mechanics. An operator's UTXO is split into reserves (deposit capacity) and collateral (security bond), both held in the same Taproot output controlled by the quorum. If the operator misbehaves, the quorum confiscates the collateral directly from the operator's own ledger.

## Quorum Membership

### Joining

An operator requests another operator to join their quorum. The request includes:

- The member's pubkey
- Fee limits the member imposes (minimum fees the operator must charge)

If the member accepts, the operator appends `QuorumAddMember` (disc 43) to their own ledger, and the member appends `QuorumJoin` (disc 46) to their own ledger. This creates a two-sided auditable record.

`QuorumAddMember` **stages** the member: they are appended to a pending list (`next_quorum_members` in the state model) and gain no voting power yet. A subsequent `QuorumBegin` promotes all staged members to active in a single atomic step (see below). This lets an operator add several members across separate ledger updates and activate them together.

To serve as a quorum member, an operator must have at least `min_member_collateral` collateral at stake on their own ledger(s). This ensures quorum members have skin in the game — misbehavior as a quorum member (e.g., co-signing a non-conforming update) can result in slashing on their own ledger.

### Member Terms

When joining, each member specifies:

- **min_fee_bps**: minimum annualized fee rate (basis points) the operator must charge
- **min_fee_fixed**: minimum annualized fixed fee (msats/year)
- **max_fee_period**: maximum fee collection period (blocks)
- **membership_until**: block height until which the member commits to serving

The operator cannot open deposits with fees below the strictest member's minimums. This protects members from inheriting unprofitable obligations after a custody transfer.

- **max_descriptor_bytes**: maximum serialized descriptor size (bytes) the member will accept on deposits they may inherit after custody transfer

Members also specify timing parameters that govern protocol obligations (see DEP-11):

- **dispute_response_blocks**: blocks before a member must respond to embedded fraud evidence
- **dispute_arm_blocks**: blocks after `DisputeEnter` during which members must arm for the lottery
- **service_response_blocks**: blocks before an unprocessed signed request becomes provable censorship
- **max_transfer_timeout_blocks**: maximum `timeout_height` distance for `TransferLock`

The strictest (smallest) values across all members apply to the quorum. The operator cannot open deposits with descriptors exceeding the quorum's `max_descriptor_bytes` limit.

Members also specify compensation terms — the operator commits to pay each member a share of collected fees (see DEP-07) in exchange for co-signing:

- **compensation_bps**: basis points of collected fees that flow to this member (default 300 = 3%). With Q=7 members at the default, ~21% of fee revenue is distributed to cosigners.
- **compensation_deposit_id**: deposit on the operator's ledger where the member's share lands. The deposit MUST exist when `QuorumAddMember` is appended.
- **compensation_frequency_blocks**: cadence at which accrued compensation is paid out (default 2016 ≈ 2 weeks, mirroring the default fee-collection cycle).

These fields are per-member, not reduced to a quorum-wide minimum — different members can negotiate different rates. Omitting them means the member waived compensation.

### QuorumBegin (disc 12)

`QuorumBegin` does two things atomically:

1. **Promotes the staged membership.** The pending set (`next_quorum_members`, populated by `QuorumAddMember`) **replaces** the active voting set wholesale. Anything not in the staged set at `QuorumBegin` time is dropped. This means refreshing an existing quorum requires re-staging every member the operator wants to keep by issuing a fresh `QuorumAddMember` for each before the new `QuorumBegin`.
2. **Rotates the on-chain multisig.** The operator spends the old reserves UTXO into a new Taproot output whose script reflects the new active member set (see DEP-03).

After `QuorumBegin`, every subsequent update MUST carry co-signatures from a strict majority (`floor(n/2) + 1`) of the new active quorum. This prevents the operator from maintaining parallel chains — a majority of cosigners will have seen and validated the canonical chain before signing any new update. `QuorumBegin` also records the `quorum_expiry` (shortest membership duration) and `collateral_amount_msats`.

**The first `QuorumBegin` (applied from `PreQuorum`) itself MUST carry cosignatures from `floor(n/2) + 1` of the staged set** (n = `len(next_quorum_members)` at apply time). Without this rule the operator could unilaterally transition the ledger to Active with a fabricated member list or a reserves outpoint that doesn't exist on-chain — there is no active quorum yet to refuse a bad update, and post-transition the operator is trusted only because the active quorum attested the rotation. Validators MUST reject a first `QuorumBegin` that lacks this majority, and cosigners MUST verify the reserves UTXO exists, is unspent, carries the declared value, and has a network-dependent minimum number of confirmations before signing (see DEP-03 §QuorumBegin for thresholds). The operator cannot issue a `QuorumBegin` against an empty staged set — it must have first issued one or more `QuorumAddMember` operations.

**Pre-release size cap.** Validators reject any `QuorumBegin` whose total size (operator + staged cosigners) exceeds `MAX_QUORUM_SIZE_POLICY = 8`. This is a policy cap, not a protocol cap — the dispute lottery (see DEP-03 §Custody Lottery) supports up to N=15 disputants, but until production reliability data justifies going higher we limit total quorum size to 8 (so at most 7 cosigners can dispute the operator's custody). Lifting this cap is a one-line constant change with no script or wire-format implications.

### Removing Members

`QuorumRemoveMember` (disc 44) takes effect **immediately** on the ledger — the named member is dropped from both the active set and the pending set on apply. No subsequent `QuorumBegin` is required for the member to lose voting rights. However, the on-chain Taproot UTXO still encodes the pre-remove member set, so spends continue to require the removed member's signature until the next `QuorumBegin` rotates the multisig. This creates a window in which ledger-level cosig thresholds use the shrunken quorum while on-chain spends cannot proceed without the departing member — operators typically follow a `QuorumRemoveMember` with a `QuorumBegin` in the next ledger update to close the window.

Unlike `QuorumAddMember` (staged) the remove is immediate because the point of removing a member is usually that they have misbehaved or gone silent; making the operator wait until the next rotation to strip voting rights would let a captured member keep vetoing updates in the meantime.

## Collateral

Collateral is a portion of the operator's own UTXO, held in the same Taproot output as reserves. The quorum controls both reserves and collateral. If the operator misbehaves, the quorum confiscates the collateral directly — no cross-ledger coordination required.

### Structure

The operator's UTXO is split into two portions:

    UTXO = reserves + collateral

- **Reserves**: the deposit capacity — wallets can deposit up to this amount
- **Collateral**: the security bond — cannot be used for deposits, at risk of slashing

Both live in the same Taproot output, controlled by the same quorum via tiered spending paths (see DEP-03). Both `reserves_amount_msats` and `collateral_amount_msats` are declared in `LedgerOpen` and `QuorumBegin`. Co-signers MUST verify that `reserves_amount_msats + collateral_amount_msats` equals the on-chain UTXO value (in msats). `QuorumBegin` may update either value (e.g., to adjust the ratio), subject to quorum member agreement via co-signature.

### Slashing

When the operator is proven non-conforming (see DEP-06), the quorum confiscates the entire UTXO. The collateral portion is the operator's real loss — deposits are owed back to depositors, but the collateral is forfeited. The lottery winner (see DEP-03) takes over the ledger, inherits obligations, and retains the collateral as compensation for assuming custody.

If the operator misbehaves as a **quorum member** on another operator's ledger (e.g., co-signs a non-conforming update), proof of this misbehavior can be presented to the misbehaving member's own quorum, triggering slashing on their own ledger.

### Multi-Ledger Operators

Operators SHOULD run multiple ledgers (recommended: 3-5) with **independent quorums** per ledger. This provides:

1. **Probabilistic safety**: an attacker must compromise all quorums simultaneously to avoid losing collateral. With Q=5 at 33% adversarial, P(all 5 ledgers compromised) < 0.004%.
2. **Partial confiscation**: misbehavior on one ledger triggers slashing on the others, as the honest quorums on remaining ledgers detect and act.
3. **Capital efficiency**: the same total UTXO is split across ledgers, each with independent security.

The UTXO is split evenly: each ledger gets UTXO/L in reserves and UTXO/L in collateral (for L ledgers).

## Obligation Limits

A ledger's total obligations — the sum of every deposit's `balance` — must not exceed the reserves amount (from QuorumBegin). This is enforced when creating new funding offers or invoices (see DEP-10).

### Balance Accounting Model

Each deposit has two fields:

- **`balance`**: the total obligation the operator owes for this deposit (msats). This is the authoritative figure counted toward the ledger's obligations.
- **`locked_balance`**: a subset of `balance` that is currently earmarked for in-flight operations (pending transfers, invoice locks). It is not a separate bucket of funds and is not additive with `balance`.

Per-deposit spendable funds are `available_balance = balance - locked_balance`. Locking funds for an in-flight operation does not change the deposit's `balance` or the ledger's total obligation — the funds were already counted. Only settlement (credit/debit/fulfill) changes `balance`.

### Security Model

Consider an operator with UTXO = U, reserves fraction R, collateral fraction C = 1-R:

- **Per ledger**: reserves = U×R/L, collateral = U×C/L (for L ledgers)
- **Attack gain**: at most U×R/L per compromised ledger (stolen deposits)
- **Attack cost**: U×C/L per ledger where quorum retains honest majority (collateral slashed)

With R=40%, C=60%, L=5: each compromised ledger yields 0.08U in stolen deposits, but each slashed ledger costs the attacker 0.12U. The attacker must compromise more ledgers than they lose — which requires controlling majority of most quorums simultaneously.

Simulation results (N=50 operators, Q=5, 500 trials, sybil-optimal attacker):

| Reserves | Collateral | L | Max safe sybil% |
|:---:|:---:|:---:|:---:|
| 50% | 50% | 1 | 29% |
| 50% | 50% | 3 | 35% |
| 50% | 50% | 5 | 39% |
| 40% | 60% | 5 | 49% |
| 33% | 67% | 3 | 49% |

See PROPOSAL.md for full simulation methodology and parameter sweep.

## Co-Signer Obligations

Quorum members must maintain a full state replica of any ledger they co-sign for. Before co-signing an update, the member MUST verify:

1. **Chain continuity**: the update's `previous_hash` matches the member's last validated `chain_hash`
2. **State validity**: the operation can be applied to the member's local state replica without error (deposit exists, sufficient balance, valid fees, etc.)
3. **Obligation limits**: the running total of obligations does not exceed reserves
4. **Collateral preservation**: operations do not reduce the collateral portion below `collateral_amount_msats`
5. **No dispute filed**: the member has not filed a dispute fork for this ledger

If any check fails, the member MUST refuse to co-sign. The chain continuity check (1) is the primary defense against parallel chains — if the operator has published a non-conforming update that the member rejected, subsequent updates will have a different `previous_hash` and the member will refuse.

### Majority Requirement

After `QuorumBegin`, every update requires `floor(n/2) + 1` co-signatures from distinct quorum members. This ensures a majority of the quorum has validated every update. Since each cosigner verifies chain continuity from their own tip, the operator cannot obtain a majority for two different updates at the same sequence number — at least one member of any majority will have already signed the other version and will refuse.

### Conformance

Co-signing without state validation is non-conforming — a member who co-signs an update that violates obligation limits is complicit in the violation and may have their own collateral slashed on their own ledger(s).

### Membership Duration

Quorum membership duration is limited by `quorum_expiry` — the shortest member's `membership_until`. Before this block, the operator must refresh the quorum via a new `QuorumBegin`.

### Confiscation

If the operator is proven non-conforming (see DEP-06), the quorum confiscates the operator's UTXO. The collateral portion is forfeited; deposit obligations are transferred to the new custodian. This is the primary economic deterrent against operator misbehavior.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumAddMember, QuorumRemoveMember, QuorumJoin, QuorumBegin fields)
- [DEP-03](DEP-03.md): On-chain transactions (reserves rotation, tapscript multisig, collateral in UTXO)
- [DEP-06](DEP-06.md): Fraud proofs and recovery (quorum members initiate disputes, confiscation)
- [DEP-07](DEP-07.md): Fee schedules (fee limits negotiated by quorum members)
- [DEP-10](DEP-10.md): Payment channels (obligation limits enforced at offer/invoice creation)
- [DEP-11](DEP-11.md): Time obligations (quorum rotation)
- [DEP-12](DEP-12.md): Certified delivery (service_response_blocks enforcement)
