# DEP-03: On-Chain Transactions

## Abstract

This document specifies the on-chain transaction formats used by Bitcoin Deposits: the reserves UTXO structure, tapscript multisig construction for quorum spending, reserves rotation transactions, and the lottery mechanism for contested custody transfers.

## Reserves UTXO

A ledger's reserves are held in a single UTXO with an amount greater than or equal to the sum of the ledger's obligations (total deposit balances + locked amounts). The UTXO is spendable by:

1. **Quorum majority**: a threshold of quorum members can spend cooperatively (for rotation or recovery)
2. **Operator fallback**: the operator can spend unilaterally after a lengthy timelock (for recovery when quorum members are unavailable)

## Tapscript Construction

The reserves UTXO uses a Taproot output with a tapscript tree containing tiered spending paths. The internal key is an unspendable point (no key-path spend). All spending goes through script-path reveals.

### Spending Tiers

The `quorum_expiry` block (shortest member's `collateral_lock_until`) determines the timelock structure:

1. **Full quorum** (k-of-n): no timelock. Available immediately. This is the normal operating path for rotation and recovery.

2. **Degraded quorum** (k-1 of n): available before `quorum_expiry`. This allows the remaining members to initiate a new `QuorumBegin` if one member disappears. The degraded window should be early enough that the new quorum can be established before collateral expires. Suggested: `quorum_expiry - 2016` (~2 weeks before expiry).

3. **Operator solo**: available well after `quorum_expiry`. This is the absolute last resort when the entire quorum is unresponsive. Suggested: `quorum_expiry + 8640` (~2 months after expiry).

The degraded path predating `quorum_expiry` is critical: letting the quorum expire without rotation is non-conforming (see DEP-11), so the mechanism to prevent that must be available before expiry.

## QuorumBegin (disc 12)

When a quorum is established or refreshed, the operator constructs a new Taproot output and broadcasts a transaction spending the old reserves to the new address. The `QuorumBegin` operation records:

- **reserves_id**: the new Taproot address
- **reserves_amount**: the amount in the new output (msats)
- **spending_txid**: the txid spending the old reserves
- **new_outpoint_txid**: the txid of the new reserves output
- **new_outpoint_vout**: the vout index
- **quorum_members**: the pubkeys included in the new multisig
- **quorum_expiry**: block height when the quorum expires (shortest member collateral lock)
- **total_collateral**: sum of attested collateral across all members (msats)

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

- The full reserves output goes to the lottery
- Excess reserves (above obligations) are split equally among quorum members
- Collateral on other ledgers may be confiscated by those operators

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (QuorumBegin, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-05](DEP-05.md): Quorum membership determines multisig participants
- [DEP-06](DEP-06.md): Dispute lifecycle triggers the lottery
