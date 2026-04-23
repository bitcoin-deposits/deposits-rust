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

The on-chain UTXO value MUST equal `reserves_amount + collateral_amount`. Co-signers MUST verify this before signing.

After `QuorumBegin`, co-signatures become required for all subsequent updates. A new `QuorumBegin` MUST be appended before `quorum_expiry` (see DEP-11).

### On-Chain State Anchor

The reserves rotation transaction should include an `OP_RETURN` output containing the `chain_hash` at the `QuorumBegin` sequence. This gives wallets an on-chain anchor to verify that the ledger state on relays matches the operator's committed state at the time of rotation — without trusting any relay. The `OP_RETURN` output is:

    OP_RETURN <chain_hash (32 bytes)>

This is cheap (one additional output on a transaction the operator is already making) and provides a verifiable checkpoint for wallets that suspect relay censorship or data loss.

## Lottery

When a ledger becomes contested (dispute), quorum members compete for custody via a preimage-based lottery:

1. Each member publishes `DisputeArmed` with a `commitment_hash` (HASH160 of a secret preimage) and a `target_reserves` address
2. After an entropy block is mined, preimages are revealed
3. The winner is determined by which preimage, combined with the entropy block hash, produces the lowest value
4. The winner appends `DisputeAcquire`, spending the reserves to their target address
5. Losers append `DisputeYield`

### Respectful Custody

When a ledger becomes unavailable (not provably dishonest), the custody transfer is respectful:

- Only the amount required to cover obligations is sent to the lottery winner
- Change is sent back to the original operator's pubkey
- Collateral control is unaffected

### Non-conformance

When proof of non-conformance is provided:

- The full UTXO (reserves + collateral) goes to the lottery
- The lottery winner takes over the ledger and inherits deposit obligations
- The collateral portion is forfeited by the operator — the winner retains it as compensation
- Excess reserves (above obligations) are split equally among quorum members

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumBegin, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-05](DEP-05.md): Quorum membership determines multisig participants
- [DEP-06](DEP-06.md): Dispute lifecycle triggers the lottery
