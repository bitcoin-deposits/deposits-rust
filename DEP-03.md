# DEP-03: On-Chain Transactions

## Abstract

This document specifies the on-chain transaction formats used by Bitcoin Deposits: the reserves UTXO structure, tapscript multisig construction for quorum spending, reserves rotation transactions, and the lottery mechanism for contested custody transfers.

## Reserves UTXO

A ledger's reserves are held in a single UTXO with an amount greater than or equal to the sum of the ledger's obligations (total deposit balances + locked amounts). The UTXO is spendable by:

1. **Quorum majority**: a threshold of quorum members can spend cooperatively (for rotation or recovery)
2. **Operator fallback**: the operator can spend unilaterally after a lengthy timelock (for recovery when quorum members are unavailable)

## Tapscript Construction

The reserves UTXO uses a Taproot output with a tapscript tree containing:

- One leaf per valid quorum spending combination (k-of-n threshold)
- One leaf for the operator's fallback timelock path

The internal key is an unspendable point (no key-path spend). All spending goes through script-path reveals.

## QuorumBegin (disc 12)

When a quorum is established or refreshed, the operator constructs a new Taproot output and broadcasts a transaction spending the old reserves to the new address. The `QuorumBegin` operation records:

- **reserves_id**: the new Taproot address
- **reserves_amount**: the amount in the new output (msats)
- **spending_txid**: the txid spending the old reserves
- **new_outpoint_txid**: the txid of the new reserves output
- **new_outpoint_vout**: the vout index
- **quorum_members**: the pubkeys included in the new multisig
- **first_expiry_block**: earliest quorum member expiry

After `QuorumBegin`, co-signatures become required for all subsequent updates.

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
