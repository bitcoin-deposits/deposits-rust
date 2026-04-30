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
3. Append `DisputeArmed` with a commitment hash (HASH160 of a secret preimage) and target reserves address

### Lottery

The lottery determines which quorum member takes custody of the disputed ledger. Selection happens *on chain*, enforced by a Tapscript that only lets the script-determined winner spend the lottery output. Off-chain agreement on the outcome is not required. See DEP-03 §"Custody Lottery" and `CUSTODY_LOTTERY.md` for full script construction details.

#### Phase 1: Commitment (DisputeArmed)

Each participating quorum member appends `DisputeArmed` to their fork with:

- **commitment_hash**: `HASH160(preimage)` where `preimage` is a 17-to-`(16+N)`-byte random value chosen by the member. The preimage's *length* contributes the entropy: `contribution = LEN(preimage) - 16` lies in `1..=N`.
- **target_reserves**: the bitcoin address where the member wants their winnings sent if they win
- **armed_block**: the block height at time of arming

Members must arm within `dispute_arm_blocks` after `DisputeEnter`. Late entries are excluded. `dispute_arm_blocks` is recorded in `QuorumAddMember` so all parties agree on the obligation at join time.

The participant ordering (canonical, derived from sorted `quorum_pubkey`) and the committed hashes go into the lottery script that the confiscation transaction will lock funds into.

#### Phase 2: Confiscation

After the arm window closes, the recovery quorum (quorum members minus the disputants — the disputed operator + non-arming members) cosigns a confiscation transaction that spends the disputed reserves UTXO to a new Taproot output: the **lottery output**. Its tapscript tree contains:

- A primary lottery claim leaf that dispatches to the `(sum mod N)`-th disputant on full reveal
- For N≥11, K=1 partial-reveal leaves at CSV 72 (one per missing disputant) that handle the dominant single-non-revealer case
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

**Respectful** (unavailability without proven fraud):
- Only the amount covering the ledger's obligations goes to the winner
- Change (including collateral) is returned to the original operator's pubkey

**Punitive** (proven non-conformance):
- The full UTXO (reserves + collateral) goes to the winner
- The winner inherits deposit obligations and retains the collateral as compensation
- Excess reserves (above obligations) are split equally among quorum members
- If the operator runs multiple ledgers, proof of non-conformance on one ledger can be presented to the other ledgers' quorums, triggering slashing there as well

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
