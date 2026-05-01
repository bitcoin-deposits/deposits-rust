# Chapter 11: Fraud Proofs

> **Audience**: developers, operators, integrators, advanced wallet users
> **Prereqs**: chapters 4, 7, 8 (also chapters 6 and 9 for context)
> **DEPs**: DEP-06

## Why this chapter exists

Everything earlier in Part II — ledger updates, quorums, deposits, transfers, channel payments, fees — describes what an honest operator does. The protocol does not assume operators are honest. It assumes that misbehavior is *detectable, attributable, and slashable*. That promise is delivered by exactly one mechanism: fraud proofs.

A fraud proof is cryptographic evidence that an operator's chain contains an event that should not have been there, or omits an event that should have been there. When evidence of either kind exists, anyone — a wallet, a member, a passerby — can package it into a `FraudBroadcast`, send it on Nostr, and quorum members will treat the broadcast as a trigger to fork the operator's ledger and start the recovery pipeline. The operator's collateral is forfeit; the deposits transfer to a new custodian; the protocol is back in a conforming state.

Recovery itself — how the fork is constructed, how the lottery resolves, how the on-chain confiscation transaction is built — is the subject of [Chapter 12](12-recovery-pipeline.md). This chapter is about the proof half: what counts as evidence, how that evidence is shaped on the wire, how it gets bound to a specific operator's chain at a specific moment in time, and how a verifier mechanically determines whether a broadcast is real fraud or fabrication.

Read this chapter to understand the protocol's slashing engine. Read Chapter 12 to understand what slashing executes.

## What a fraud proof is, conceptually

The whitepaper frames fraud detection in the language of *causal ordering*. A ledger is an append-only chain. Each update is a SHA-256 chain to the previous, signed by the operator and co-signed by a majority of the quorum. Each cosignature folds in the cosigner's own latest ledger hash — `member_ledger_hash` in the wire format. So an update on operator A's ledger says, in effect: "I, A, signed this update; the other Q-1 quorum members signed too, and at the moment they signed, their own ledgers were at hashes H1, H2, ..., H_{Q-1}." Those hashes get hashed back into A's update, and the next time those members sign their own updates, A's hash gets folded in there. Every ledger that touches every other ledger eventually entangles. The whitepaper's term is the **web of causality**:

> a co-signature includes the latest update hash from the co-signer's ledger. that hash is then incorporated into the current update's hash, becoming part of the chain as well as part of all other chains that the ledger operator co-signs for, creating a web of causality. this is unable to prove time explicitly, but is able to prove that certain pieces of information were created in a specific order.

This is the trick. Bitcoin's blockchain measures absolute time only down to ~10-minute confirmation granularity, and ledger updates are not anchored on-chain. But the cosignature web measures *relative* order with single-update precision. A fraud proof exploits this: it shows that the operator's chain contains evidence of misbehavior at a sequence number after which the operator should have acted differently and didn't.

There are five fraud-proof types in the protocol; four are fully implemented and the fifth (`NonConformingUpdate`) is a placeholder slot whose verifier-side dispatch is pending. Each variant has its own evidence shape, but all share the same skeleton: prove the *evidence* itself, prove the evidence was *temporally bound* to the operator's chain (the embedding + causal chain), then prove the operator *failed to do the right thing in response*.

## The four implemented proof types

The five-variant enum lives in `deposits-protocol/src/fraud.rs`:

```rust
pub enum FraudProofType {
    UncreditedOnchainPayment,
    UncreditedLightningPayment,
    StaleCosignature,
    DisputeDereliction,
    NonConformingUpdate,  // placeholder
}
```

Each verifies against a different shape of evidence (`FraudEvidence`), and each is checked by a dedicated function in the same file: `verify_uncredited_onchain`, `verify_uncredited_lightning`, `verify_stale_cosignature`, `verify_inactive_quorum_member`. The `NonConformingUpdate` variant exists in the type but its verifier is a `// placeholder accept` branch — using it today does not slash. The intent is to wire it up to the same conformance checks `Ledger::checked_apply` runs server-side, so any rule the daemon enforces becomes a slashable claim if the operator violates it.

### StaleCosignature

The accusation: a member's cosignature on the operator's chain references a `member_ledger_hash` that was already stale at the moment the cosignature was created. The member is provably-online evidence of their own ledger having advanced past that hash before they "signed" it on the operator's chain — which means either the member backdated their attestation (signed something they shouldn't have, then claimed it was earlier) or the cosignature was forged.

Evidence (`FraudEvidence::StaleCosign`):

- `stale_update_sequence`, `stale_update_hash`: where on the operator's ledger the bad cosignature appears.
- `declared_member_hash`: the `member_ledger_hash` field that's stale.
- `member_later_sequence`, `member_later_hash`: a later update on the *member's* own ledger that proves the member was past `declared_member_hash` before the operator's update was signed.
- `member_ledger_id`: the ledger the member is operator of.

The verifier's check (in `verify_stale_cosignature`) is four temporal-ordering questions: does the operator's stale update exist at the claimed sequence with the claimed content hash; does it carry a `CosignEntry` with the `declared_member_hash`; does the member's chain reach `member_later_hash` at the claimed sequence; and crucially, did the member's chain advance past `declared_member_hash` *before or at* the operator's stale-update block height? If all four, the cosignature was demonstrably created out of order. The member (or, more precisely, whichever party actually produced that signature) backdated.

This proof type is the protocol's protection against a member who signs whatever the operator wants, dating the attestation arbitrarily. As long as the member's own ledger advances on its own schedule, any attempt to forge a cosignature with an old `member_ledger_hash` shows up in the temporal ordering.

### UncreditedLightning

The accusation: the operator created a co-signed BOLT-11 invoice. Some payer paid it. The preimage is provable (any payer who completed the payment got it back and can produce it). The operator's chain shows no `InvoiceCredit` for that payment hash. The operator received Bitcoin and didn't credit the deposit.

Evidence (`FraudEvidence::UncreditedLightning`):

- `invoice`, `payment_hash`, `deposit_id`, `amount_msat`: the invoice. The cosigner key signed a canonical message binding the operator's ledger ID, the payment hash, the deposit, the amount, and the cosigner's own ledger hash at cosign time.
- `cosigner_pubkey`, `cosigner_ledger_hash`, `cosign_signature`: the cosignature that anchors operator commitment to this invoice.
- `preimage`: 32 bytes such that `SHA256(preimage) == payment_hash`. Proof the payment succeeded.
- `proof_sequence`: an update on the operator's ledger that exists *after* the preimage was knowable. Proof the operator was alive past the moment they should have credited.

`verify_uncredited_lightning` checks four things: the preimage actually hashes to `payment_hash`; the cosignature is a valid BIP-340 schnorr signature from `cosigner_pubkey` over the canonical invoice signing message (re-derived from the proof's own fields); the operator has a SignedLedgerUpdate at `proof_sequence`; and no `InvoiceCredit` or `InvoiceFulfill` for this payment hash exists in the operator's history at sequence `≤ proof_sequence`.

The protocol cannot, on its own, observe that a Lightning payment succeeded — that's an invisible event happening on the operator's LN node. What it can observe, retroactively, is the preimage. As long as one payer is willing to surface it, the operator's silence becomes proof of theft. The whitepaper's phrasing: "the upside of stealing a single payment is bounded; the downside is existential."

### UncreditedOnchain

The accusation: the operator advertised a co-signed funding offer ("send Bitcoin to address X by block N and I'll credit deposit D"). The wallet (or a third party) sent Bitcoin to that address. The on-chain transaction has confirmed past the operator's required-confirmations threshold. The operator has signed at least one further ledger update at a block height past the confirmation deadline. There is no `OnchainCredit` for that `(txid, vout)` in the operator's chain.

Evidence (`FraudEvidence::UncreditedOnchain`):

- `offer_id`, `funding_address`, `accused_operator_pubkey`, `deadline_block`: the offer, signed by the operator and a cosigner.
- `cosigner_pubkey`, `cosigner_ledger_hash`, `cosign_signature`: the cosignature anchoring the offer.
- `txid`, `vout`, `amount_sats`: the on-chain payment.
- `confirmed_at_block_hash`: the block hash where the funding tx confirmed. The verifier looks this up against its *own* confirmed chain — the height claimed in the proof is not trusted.
- `required_confirmations`: from the offer.
- `proof_sequence`: an update on the operator's ledger that occurred at a block height at least `required_confirmations` past the funding block.

`verify_uncredited_onchain` (in `fraud.rs`) checks all of: cosignature validity, that `confirmed_at_block_hash` is in the verifier's chain, that the operator's update at `proof_sequence` is also in a confirmed block of the verifier's chain, that the elapsed blocks between the two reach the required confirmation count, and that no `OnchainCredit` for `(txid, vout)` exists in operator history at `seq ≤ proof_sequence`.

Notably, this proof is **autonomous**: a wallet has every piece of evidence it needs from the offer it received, the on-chain transaction it sent, and the operator's own subsequent updates (which the wallet can fetch from the relay). No interactive cooperation with the payer is required.

### DisputeDereliction

The accusation: a member of the disputed ledger's quorum was online during the response window after a fraud proof became knowable, but did not act on it. They are sanctioned for their inaction by losing their *own* ledger's collateral. Their accused-ledger here is their collateral ledger, not the original disputed one.

Evidence (`FraudEvidence::DisputeDereliction`):

- `original_fraud_hash`: the proof hash they ignored.
- `original_fraud_block_hash`: a block hash anchoring when the original fraud became knowable. Verifier confirms this hash is in its own confirmed chain.
- `required_response_blocks`: the negotiated window from `QuorumAddMember`.
- `member_ledger_id`, `member_pubkey`: who's accused.
- `member_active_sequence`: an update on the member's own ledger past the deadline. Its `block_hash` is also confirmed by the verifier.

`verify_inactive_quorum_member` confirms that both block hashes are in the verifier's chain, the elapsed blocks between them exceed `required_response_blocks`, and the update at `member_active_sequence` is signed by `member_pubkey` (so an attacker can't plant an update on a third party's ledger and blame the wrong member).

This proof type is the recursive case: it slashes members who fail to slash. Without it, the whitepaper's "incentivized predator" model of quorum members becomes asymmetric — the upside of acting on fraud is taking over a ledger, but the downside of inaction would be nothing. With it, a member who sees fraud and ignores it is subject to slashing on their own ledger by *that* ledger's quorum, recursively. The trust assumption from [Chapter 2](02-mental-model.md) — at least one honest member per quorum — propagates through the whole network because every member's collateral is on the line.

### NonConformingUpdate (placeholder)

The fifth variant is reserved for the case where the operator signs a ledger update that violates protocol rules — over-promising against reserves, fee underflow, sequence gap, deposit balance going negative, dispute-state mismatch, anything `Ledger::checked_apply` would reject. The evidence shape is just the offending update (`update_b64`) and a free-text `violation` description.

The verifier-side dispatch is intentionally a placeholder accept right now (`fraud.rs:954` — "not yet implemented at this layer"). Until the dispatch is wired to the same conformance checks `validate_operation` runs server-side, this proof type does not slash. Wiring it up is on the roadmap, and the work is mostly engineering — the conformance machinery already exists in `deposits-core/src/operation_validation.rs`. The reason it isn't done yet is that the broader test surface for "every conformance violation slashes" needs to be built alongside; doing it incrementally would make some violations slashable and others not, which is worse than leaving the whole class disabled.

## The shape of a fraud proof

Two on-the-wire shapes, layered:

```rust
pub struct FraudProof {
    pub proof_type: FraudProofType,
    pub accused: String,          // hex pubkey
    pub ledger_id: String,        // hex ledger id
    pub evidence: FraudEvidence,  // variant-specific
}

pub struct FraudBroadcast {
    pub proof: FraudProof,
    pub embedding: ProofEmbedding,
    pub causal_chain: Vec<CausalLink>,
}
```

The `FraudProof` is the hashable evidence document. Its `proof_hash()` method emits a 32-byte digest using BIP-340 tagged hashing (tag = `"deposits/fraud_proof"`), serializing `proof_type`, `accused`, `ledger_id`, and the evidence's canonical bytes. This 32-byte hash is what gets *embedded* into a ledger so the rest of the protocol can prove "this evidence existed at or before time T."

The `FraudBroadcast` wraps the proof with the temporal-binding metadata. The `embedding` says *where* the proof hash was placed (a ledger ID, a sequence number, a content hash, and the field — typically `"transfer_nonce"` or `"delivery_request_hash"`). The `causal_chain` is a sequence of `CausalLink`s connecting the embedding ledger to the accused ledger if they aren't the same. Each link is a co-signed update on one ledger that includes a `member_ledger_hash` from another, proving the temporal ordering.

```rust
pub struct ProofEmbedding {
    pub ledger_id: String,
    pub sequence: u64,
    pub update_hash: String,    // content_hash of the embedding update
    pub field: String,          // e.g. "transfer_nonce"
}

pub struct CausalLink {
    pub ledger_id: String,        // ledger this co-signed update is on
    pub sequence: u64,
    pub update_hash: String,
    pub member_ledger_hash: String,  // from the previous link's ledger
    pub source_ledger_id: String,    // which ledger that hash came from
}
```

Broadcasts ship as Nostr `Kind:9101` events. The constant lives at `deposits-protocol/src/fraud.rs:1109` (`KIND_FRAUD_PROOF`).

## Causal chains and embeddings, in detail

The whole point of the embedding-plus-chain machinery is to prove, without a clock, that the evidence came *first*. The construction goes like this.

A wallet (or a member acting on its behalf) wants to produce a fraud proof against operator A's ledger L_A. The wallet:

1. Builds the `FraudProof` and computes its 32-byte `proof_hash`.

2. Gets that hash embedded into *some* ledger. Embedding choices, in order of preference (DEP-06 §"Embedding"):
   - **Direct**: directly into operator A's own ledger L_A, as the `nonce` of a self-transfer or as the `delivery_request_hash` of a `DeliveryEmbed` update. The operator signs it; the embedding is now part of L_A.
   - **One hop**: into a quorum member's ledger L_M. The embedding rides until the next time the member co-signs an update on L_A — at which point the member's ledger hash (which now includes the embedded proof hash) gets folded into the cosignature's `member_ledger_hash`, and from there into A's update.
   - **Further**: into any ledger the member is connected to. The proof waits for causal propagation through one or more cosignature hops to reach L_A.

3. Once the embedding is causally connected to L_A, the wallet collects the `CausalLink`s — one per intermediate co-signed update — and ships the `FraudBroadcast`.

The verifier doesn't search. Verification is a strict link-by-link walk:

- Start with `embedding.ledger_id`. Confirm the proof hash is actually present in the update at the claimed sequence (in a field that supports embedding — `LedgerOperation::embedded_hash` returns the hash if it's there, `None` if not).
- For each `CausalLink` in order: confirm there's a co-signed update on `link.ledger_id` at `link.sequence` whose `member_ledger_hash` matches `link.member_ledger_hash`, and whose source is `link.source_ledger_id` — which must equal the previous link's `ledger_id` (or, for the first link, the embedding ledger).
- Confirm the *last* link's `ledger_id` is the accused operator's `ledger_id`.

`FraudBroadcast::verify_chain_structure` does the structural check (link sequencing, source matching, terminal ledger). `verify_fraud_broadcast` is the top-level composer: it does structural sanity, embedding presence, causal-chain presence, and finally the per-type evidence verification.

Direct embedding has an empty causal chain. One-hop has a single link (the operator's update co-signed by the member who carried the embedding). Two hops would have two links. The chain structure is rigid — every transition is exactly an attested causal step.

The reason this machinery is needed at all is the temporal half of the proof. For `UncreditedLightning`, the verifier needs to know that the operator was alive past the moment the preimage was knowable. The "moment knowable" is anchored by the embedding: once a hash of the preimage-revealing evidence is in the chain, every subsequent update implicitly attests "the operator was at sequence S after the embedding was at sequence E_embed." For `StaleCosignature`, the embedding isn't even necessary for the temporal ordering — that's already proven by the cosignature web — but it is required for getting the broadcast accepted by verifiers, who refuse anything not anchored.

## A worked example: an uncredited Lightning payment

A concrete walk-through, end to end. Bob holds a deposit on operator A's ledger L_A. Carol wants to pay Bob 100,000 msat over Lightning.

1. **Bob's wallet asks A** to mint a BOLT-11 invoice for 100,000 msat against Bob's deposit. A's daemon constructs the invoice, requests cosignatures from a majority of L_A's quorum (call them M1, M2, M3), commits an `InvoiceLock` operation on L_A, and returns the cosigned invoice to Bob.

2. **Carol pays the invoice.** Her LN node forwards through the Lightning network, A's LN node receives the payment, A claims the HTLC by revealing the preimage. Carol's wallet now holds the preimage as a receipt. Bob's wallet knows the payment hash from the invoice but not the preimage.

3. **A doesn't credit.** A's daemon should (by the protocol, as a conformance obligation) commit an `InvoiceCredit` on L_A, increasing Bob's deposit balance by 100,000 msat. It doesn't. Bob's wallet sees no balance change.

4. **Bob asks Carol for the preimage.** Out of band — chat, payment-receipt screenshot, anything. Carol cooperates. Bob's wallet now has `(invoice, payment_hash, preimage)` and verifies `SHA256(preimage) == payment_hash`. Confirmation of payment.

5. **Bob's wallet builds the FraudProof.**
   - `proof_type = UncreditedLightningPayment`
   - `accused = A's pubkey`
   - `ledger_id = L_A`
   - `evidence = UncreditedLightning { invoice, payment_hash, deposit_id (Bob's), amount_msat: 100000, cosigner_pubkey: M1's, cosigner_ledger_hash: M1's-at-cosign-time, cosign_signature: M1's BIP-340 sig, preimage, proof_sequence: latest seq on L_A }`

   The `proof_hash` is computed.

6. **Bob escalates.** Bob's wallet sends a `delivery_embed` request to one of L_A's quorum members (say M1) — see [Chapter 15](15-delivery-escalation.md) for the protocol. The request payload includes the proof hash. M1 commits a `DeliveryEmbed` update on L_A (this is the wallet's bounty — Bob pays M1 a small fee for the embedding, and M1 has the ledger access to commit the update). Now the proof hash is bound into L_A at sequence E_embed.

7. **M1 verifies.** M1 already had to verify the request to commit it, but separately, the delivery-embed mechanism gives M1 the evidence to construct the proof itself. M1 (or Bob, or anyone watching the relay) constructs the `FraudBroadcast`:
   - `proof` as built above
   - `embedding = ProofEmbedding { ledger_id: L_A, sequence: E_embed, update_hash: <M1's update content_hash>, field: "delivery_request_hash" }`
   - `causal_chain = []` — direct embedding; no hops needed.

8. **Publish.** The broadcast is published to the relay as a Nostr `Kind:9101` event.

9. **The other members verify.** M2 and M3 receive the broadcast. Each runs `verify_fraud_broadcast`:
   - Structural: chain is empty, embedding ledger == accused ledger — direct embedding rule passes.
   - Embedding present: the proof hash is at `E_embed` on L_A in the `delivery_request_hash` field — pass.
   - Per-type evidence (`verify_uncredited_lightning`): preimage hashes to payment_hash — pass; cosignature is valid BIP-340 — pass; proof_sequence exists on L_A — pass; no `InvoiceCredit` for this payment_hash at any seq ≤ proof_sequence — pass.

10. **Pipeline triggers.** Each member's daemon advances the disputed ledger from "armed" to "confiscation pending." This is where Chapter 12 picks up — fork, lottery, on-chain confiscation transaction. The four integration tests under `deposits-test/tests/fraud_proof_*.rs` exercise this flow end-to-end on a Q=3 cluster, one per proof type, polling for the on-disk `confiscated_<ledger-prefix>.marker` to confirm pipeline completion.

## Verifier discipline

Verification is fastidiously chained, never searched. Every step has a specific check, every check has a specific error message, no step is "scan history for X." The discipline matters because broadcasts arrive over Nostr — a transport with no inherent authentication — and a fabricated broadcast must always fail verification deterministically.

The four pure verifiers in `fraud.rs` (`verify_stale_cosignature`, `verify_uncredited_lightning`, `verify_uncredited_onchain`, `verify_inactive_quorum_member`) take the proof, the relevant ledger histories as slices, and (for the on-chain proofs) a `BlockOracle` callback that returns block heights for known block hashes. They are pure functions: no I/O, no relay queries, no bitcoind RPC. The daemon supplies the inputs; the function returns `Ok(())` or the first reason for rejection.

The `BlockOracle` deserves a note. Block heights claimed in the proof are never trusted: only block *hashes* are. The verifier's daemon implementation looks each hash up against its own bitcoind/esplora and reads the height *out of its own chain*. This means a verifier with a different chain view from the prover (different fork, different Bitcoin network, different anything) cannot be fooled into accepting a proof whose temporal ordering only works in the prover's view. The on-chain temporal claims — confirmation depth, response window — are decided by the verifier's chain.

The composed `verify_fraud_broadcast` adds two more layers: structural sanity (`verify_chain_structure`) and embedding-and-causal-chain presence (does the embedding update exist where the proof claims, does each causal link match its ledger). Only after all that does it dispatch to the per-type verifier.

Cosignature verification on the *operator's* updates inside the causal chain — confirming each link's update is actually signed by the operator and the cosigners — is not yet centralized in this layer (see the comments in `verify_uncredited_lightning` and `verify_uncredited_onchain`). The cosignature on the *evidence itself* (e.g., the cosignature on the cosigned invoice) is checked in the per-type verifier. Closing the gap is on the roadmap, alongside the `NonConformingUpdate` dispatch.

## Limits

Three things fraud proofs deliberately do not detect.

**Operator equivocation.** An operator who maintains two divergent histories of the same ledger — different sequence-N updates with different cosigner sets — is not directly slashable by a fraud proof of the four types above. Equivocation has its own detection mechanism, covered in [Chapter 14](14-equivocation-defense.md). The short version: members and wallets look for two valid signed updates with the same `(ledger_id, sequence_number)` but different `content_hash`, package them as evidence, and trigger a different slashing path. As of writing, equivocation has unit-test coverage and a Tier-3 broadcast test (`equivocation_broadcast.rs`); first-class `FraudProofType::Equivocation` integration is still pending.

**Unanimous quorum collusion.** If every member of a ledger's quorum colludes with the operator to misbehave, no fraud proof will be assembled — there's no honest party to construct it. This is the trust-assumption failure case from [Chapter 2](02-mental-model.md). The protocol cannot save deposits on a fully-collusive ledger. What it can do is make collusion expensive: each colluding member also has their own ledger with its own quorum and its own collateral, and a coordinated attack across all of them requires compromising every one of those quorums simultaneously. The math is laid out in `defend_49pct.rs` and the whitepaper's economic-deterrence argument.

**Censorship without evidence.** An operator who silently ignores a wallet's transfer request leaves no trace. There's nothing to construct a fraud proof from until the wallet *escalates* via the delivery-embed mechanism (Chapter 15) — which is precisely how silent censorship gets converted into evidence. The wallet's escalation forces the request hash onto the ledger via a member; if the operator still doesn't act after the embedded request, the wallet can construct a fraud proof from the embedded but unfulfilled request. The whitepaper's framing: the wallet's escalation is effectively a bounty on its own request.

These three limits are the protocol's stated security boundary. Within them, fraud proofs are the slashing engine. Outside them, the protocol does not promise.

## Where this leads

A fraud proof, once verified, doesn't slash anything by itself. It triggers the *recovery pipeline*: the disputed ledger gets forked from the last conforming sequence, the surviving quorum members enter a custody lottery, the winner takes over as new operator, and the on-chain confiscation transaction sweeps the operator's UTXO into the lottery output. [Chapter 12](12-recovery-pipeline.md) walks through that machinery: how `DisputeEnter` and `DisputeArmed` are constructed, what `auto_arm` and `auto_confiscate` do in the daemon, how the on-chain transaction is built. Read that chapter to understand what slashing actually executes — this chapter showed you what makes it fire.
