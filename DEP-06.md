# DEP-06: Fraud Proofs and Recovery

## Abstract

This document specifies the fraud proof construction, embedding, and broadcast mechanism, as well as the custody dispute and recovery protocol for Bitcoin Deposits.

## Status

Placeholder -- to be extracted from the reference implementation.

## Scope

### Fraud Proof Types

1. **Uncredited on-chain payment**: operator saw confirmations but didn't credit
2. **Uncredited lightning payment**: preimage revealed but deposit not credited
3. **Stale co-signature**: member_ledger_hash precedes the member's own later hash
4. **Inactive quorum member**: was active but didn't act on fraud evidence
5. **Non-conforming update**: operator signed an invalid state change

### Proof Construction

- Evidence is hashed: `SHA256(tag || tag || type || accused || ledger_id || evidence_bytes)` where `tag = SHA256("deposits/fraud_proof")`
- The 32-byte hash is embedded as a transfer nonce (TLV field 210) on the operator's ledger or a connected ledger
- Once the operator signs an update containing the hash, the evidence is causally ordered

### Causal Chain

- A fraud broadcast contains: proof + embedding location + causal chain
- Each causal link is a co-signed update on ledger X with `member_ledger_hash` from ledger Y
- Direct embedding (on the operator's ledger): empty chain
- One hop (on a quorum member's ledger): one link (the co-signed update that entangles)
- Longer paths: multiple links through the web of causality

### Custody Dispute

- Quorum members detect fraud (via Kind 9101 broadcasts or direct observation)
- Create a fork of the disputed ledger from the last valid sequence
- Publish `DisputeEnter` and `DisputeArmed` on the fork with commitment hash
- Coordinate lottery to determine new custodian

### Recovery

- Members spend previous reserves output to a lottery of candidate chains
- Winner appends `DisputeAcquire`, losers append `DisputeYield`
- Respectful custody: only obligation amount goes to lottery, change to operator
- Non-conformance: excess reserves split among quorum, collateral confiscated

## Related DEPs

- [DEP-02](DEP-02.md): Ledger State Model (DisputeEnter, DisputeAcquire, DisputeYield operations)
- [DEP-03](DEP-03.md): On-Chain Transaction Formats (lottery transaction construction)
- [DEP-04](DEP-04.md): Peer Messaging (Kind 9101 fraud proof, Kind 9103 dispute events)
- [DEP-05](DEP-05.md): Quorum and Collateral (quorum members initiate disputes)
