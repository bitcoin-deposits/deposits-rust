# DEP-06: Fraud Proofs and Recovery

## Abstract

This document specifies fraud proof construction, embedding, broadcast, and verification, as well as the dispute and recovery protocol.

## Fraud Proof Types

1. **Uncredited on-chain payment**: operator saw sufficient confirmations (proved by block_height in signed updates) but did not credit the deposit. Wallet constructs this autonomously.

2. **Uncredited lightning payment**: operator created a cosigned invoice, received payment (proved by preimage), but did not credit the deposit. Requires the payer to provide the preimage to the wallet.

3. **Stale co-signature**: a co-signer's `member_ledger_hash` in a signed update precedes their own later hash — proving they backdated their attestation.

4. **Inactive quorum member**: a member was active (their ledger has updates after the fraud) but did not initiate a dispute within the required block window.

5. **Non-conforming update**: the operator signed a ledger update that violates protocol rules (e.g., spending more than balance, invalid fee collection).

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
3. Copy collateral attestations to the fork
4. Append `DisputeArmed` with a commitment hash (HASH160 of a secret preimage) and target reserves address

### Lottery

Members coordinate to spend the previous reserves output:

1. An entropy block is determined
2. Preimages are revealed
3. The winner (lowest hash combination) appends `DisputeAcquire`
4. Losers append `DisputeYield` (transitions to Tombstoned state)

See DEP-03 for transaction construction details.

### Recovery

Wallets continue addressing the same ledger, accepting only replies co-signed by the quorum. When co-signatures stop or fail verification, the wallet queries the network and replays ledger updates to identify custody changes.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (DisputeEnter, DisputeAcquire, DisputeYield, DisputeArmed fields)
- [DEP-03](DEP-03.md): On-chain transactions (lottery construction, respectful custody)
- [DEP-04](DEP-04.md): Peer messaging (Kind 9101 fraud proof, Kind 9103 dispute events)
- [DEP-05](DEP-05.md): Quorum and collateral (quorum members initiate disputes, collateral confiscation)
- [DEP-09](DEP-09.md): Transfers (nonce field used for proof embedding)
- [DEP-10](DEP-10.md): Payment channels (cosigned offers/invoices as evidence)
