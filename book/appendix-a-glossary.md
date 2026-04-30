# Appendix A: Glossary

> **Audience**: everyone (reference)
> **Prereqs**: none
> **DEPs**: all

Terms used throughout the book, grouped alphabetically. Chapter references point to where the concept is introduced or detailed. When the book defines a term in two places, the chapter listed here is where the definition is most fully developed.

## A

**Access control**
: The operator's gate on who may open a deposit on a ledger. Layered as denylist, pubkey allowlist, and domain attestation. See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**Actor (LedgerActor)**
: The single tokio task in the reference daemon that owns the apply path for one loaded ledger. One writer per ledger, ever. See [Chapter 19: Architecture Tour](19-architecture-tour.md).

**Advisory obligation**
: A protocol obligation whose violation is *not* slashable — only a degraded-service signal. Contrast slashable. Fee-collection cadence is the canonical example. See [Chapter 10: Fees and Time Obligations](10-fees-and-time.md).

**Apply (`LedgerState::apply`)**
: The pure state-transition function: given a current `LedgerState` and a `LedgerOperation`, produces the next state. No I/O. The cornerstone of fraud-proof verification by replay. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Armed (DisputeState)**
: A fork-branch state reached after `DisputeArmed`. Only `DisputeAcquire` or `DisputeYield` is a valid next operation. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**`armed_block`**
: The block height recorded in `DisputeArmed`. Timing reference for the arm window — late entries beyond `dispute_arm_blocks` are excluded from the lottery.

**Attestation**
: A signed statement from an attestation service binding a real-world identifier (domain, Lightning address, social handle) to an operator's pubkey. Optional; not required by the protocol. See [Chapter 17: Attestation Service](17-attestation-service.md).

**Attestation service**
: A Web2 verification provider that issues attestations. The protocol's lightest-touch concession to identity. See [Chapter 17: Attestation Service](17-attestation-service.md).

**Auto-arm / auto-confiscate / auto-reveal**
: Driver functions in `deposits-node/src/node/dispute.rs` that walk a member through the recovery-pipeline stages without human intervention. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

## B

**bLSAG**
: The ring-signature variant the protocol uses for anonymous web-of-trust attestations. See [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md).

**BIP-340**
: The Schnorr-signature standard for Bitcoin. Used for every operator and cosigner signature in the protocol, plus all on-chain Taproot spends. See [Chapter 3: Background](03-background.md).

**BIP-340 tagged hash**
: A SHA-256 derivation `SHA256(SHA256(tag) || SHA256(tag) || data)` used as the signing-message construction throughout the protocol (cosignature data, fraud-proof hashes, lottery-reveal signatures).

**Block height**
: The Bitcoin block-chain index used as the protocol's time unit. Every signed update carries one. The protocol uses block height, never wall-clock time. See [Chapter 10: Fees and Time Obligations](10-fees-and-time.md).

**Block oracle (`BlockOracle`)**
: A verifier-side callback that maps known block hashes to heights. Fraud-proof verifiers consult their *own* chain through this; block heights claimed in proofs are never trusted. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**`block_hash` (in updates)**
: The 32-byte Bitcoin block hash recorded on every signed update at sign time. Used by fraud-proof verifiers to bind operator activity to a verifier-confirmed chain.

## C

**Causal chain (`CausalLink`)**
: An ordered list of co-signed cross-ledger updates connecting a fraud-proof embedding ledger to the accused operator's ledger. Every link carries a `member_ledger_hash` from the prior link's ledger, proving temporal ordering. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**`chain_hash`**
: `SHA256(content_hash || operator_signature)`. The hash that the next update names as its `previous_hash`, locking the operator's signature into the chain. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**`chain_tip_hash`**
: The chain hash of the most recent committed update on a ledger. What the next update will name as `previous_hash`.

**`checked_apply`**
: `Ledger::checked_apply` — the conformance-checked variant of `apply`. Runs `apply` plus reserves sufficiency, witness verification, and preimage match checks. What members run before co-signing.

**Claim transaction (claim TX)**
: The Bitcoin transaction the lottery winner broadcasts to spend the lottery output to their own reserves address. Its on-chain confirmation is the only proof of who took custody. See [Chapter 5: On-Chain Transactions](05-onchain-transactions.md).

**Collateral**
: The operator's at-risk security bond. Lives in the same Taproot UTXO as the reserves; cannot back deposits; forfeitable on punitive recovery. The reference network uses a 40/60 reserves/collateral split. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**Commit (`commit_staged`)**
: The second phase of the operator's two-phase commit. Verifies cosignatures, applies the state transition, advances `chain_tip_hash`, pushes to history. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Commit-reveal**
: The randomness-extraction protocol the custody lottery uses: every disputant publishes `HASH160(preimage)` first, then reveals the preimage after the confiscation TX is mined. See [Chapter 13: Custody Lottery](13-custody-lottery.md).

**Commitment hash**
: The 20-byte `HASH160` of a disputant's secret preimage, recorded in `DisputeArmed`. The lottery script verifies preimages against this.

**Compensation (`compensation_bps`)**
: The fraction of operator-collected fees that flows to each quorum member, default 300 bps (3%) per member. The steady-state side of the predator equation. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**Confirmation depth**
: The number of Bitcoin blocks a transaction must be buried under before being treated as final. Reference values: 6 mainnet, 3 testnet/signet, 1 regtest.

**Confiscation transaction**
: The Bitcoin transaction the recovery quorum cosigns to spend the operator's reserves UTXO into a lottery output. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**Conformance**
: The full set of rules an operator must obey for an update to be valid: structural correctness, reserves sufficiency, witness validity, preimage match, dispute-state consistency. Enforced by `Ledger::checked_apply`. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**`ConformanceViolation`**
: An enum of specific rule violations returned by `apply_and_check`. See Appendix C.

**`content_hash`**
: `SHA256(sequence_number || previous_hash || message || cosig_data)`. Everything in the update except the operator signature. Recomputed by every receiver — never carried on the wire.

**Cooperative path**
: Spending a Taproot UTXO via the key path or via Tier 0 of the script tree. Single Schnorr signature, smallest on-chain footprint, the everyday case. See [Chapter 3: Background](03-background.md), [Chapter 5: On-Chain Transactions](05-onchain-transactions.md).

**Cosig / cosignature**
: A quorum member's signature on a ledger update. Required from `floor(n/2) + 1` distinct members for every post-`QuorumBegin` update. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**`CosignEntry`**
: The 129-byte record of one cosignature: 33-byte cosigner pubkey, 64-byte signature, 32-byte `member_ledger_hash`. Sorted lexicographically by pubkey before hashing.

**Cosign request / cosign round**
: The operator's fan-out to its quorum members asking them to cosign a staged update. First-N-respond; serialized one round per ledger. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**Courier**
: A wallet-shaped service that holds deposits on multiple ledgers and atomically swaps between them via HTLCs. Not a protocol primitive — a market role. See [Chapter 16: Couriers](16-couriers.md).

**Custody**
: The active control of funds on a ledger. Held by the operator; transferred on `DisputeAcquire`.

**Custody lottery**
: The on-chain commit-reveal mechanism that selects a single disputant as the new operator. Implemented as Tapscript leaves. See [Chapter 13: Custody Lottery](13-custody-lottery.md).

**Custody transfer**
: The change of operator-key on a ledger via `DisputeAcquire`. The `ledger_id` persists; the deposits stay in place; only the `parent_pubkey` rotates.

## D

**Deadline block**
: The block height past which a time-bound obligation is overdue. Slashable in some cases (uncredited on-chain), advisory in others. See [Chapter 10: Fees and Time Obligations](10-fees-and-time.md).

**`DeliveryEmbed`**
: The ledger operation (discriminant 80) a member appends to their own ledger when a wallet escalates an unprocessed request. Pure causal anchoring; state-machine no-op. See [Chapter 15: Delivery Escalation](15-delivery-escalation.md).

**Delivery escalation**
: The wallet-side mechanism for converting "the operator ignored me" into evidence anchored on a member's ledger. See [Chapter 15: Delivery Escalation](15-delivery-escalation.md).

**Deposit**
: A stable account on a ledger, identified by a 16-byte `deposit_id` derived as `SHA256(descriptor)[0..16]`. Has a balance, a locked balance, a miniscript descriptor, and a fee schedule. See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**`DepositClose`**
: The operation that removes a deposit from a ledger. Refused unless `balance == 0` and there are no outstanding invoices.

**`deposit_id`**
: A 16-byte identifier derived from the deposit's miniscript descriptor. Deterministic, allowing wallets to recover deposits from seed plus a relay.

**`DepositKeyRotate`**
: The operation that changes the miniscript descriptor controlling a deposit. Carries a witness satisfying the *old* descriptor.

**`DepositOpen`**
: The operation that opens a new deposit. Carries the descriptor, fee schedules, fee-change governance, and the `receive_requires_sig` flag.

**Depositor**
: The owner of a deposit. The party whose wallet authorizes spending from it.

**`DescriptorWitness`**
: A stack of byte arrays satisfying a deposit's miniscript descriptor against a per-operation signing message.

**Discriminant**
: The first-byte type tag in a `LedgerOperation`'s TLV encoding. Identifies which variant the operation is. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Dispute**
: The state-machine condition entered when a fraud proof is verified against an operator. Triggers the recovery pipeline.

**`DisputeAcquire`**
: The operation a lottery winner appends to their fork to record the on-chain claim transaction and rotate `parent_pubkey` to themselves.

**`DisputeArmed`**
: The operation each disputant appends to their fork to commit to the lottery: carries `armed_block`, `commitment_hash`, and `target_reserves`.

**`DisputeEnter`**
: The operation that opens a custody dispute on a fork. The one operation that may be signed by a key other than the current `parent_pubkey` — specifically, by any pubkey that was a quorum member at the fork point.

**`dispute_response_blocks`**
: The negotiated window after evidence becomes knowable, within which a quorum member must dispute or themselves become liable for an `InactiveQuorum` proof. Default 144 blocks (~1 day).

**`DisputeState`**
: The per-ledger dispute state-machine variable. Values: `Normal`, `Disputed`, `Armed`, `Tombstoned`. Per fork-branch.

**`dispute_wakeup`**
: The `tokio::sync::Notify` the daemon uses to fire `auto_confiscate` immediately on observing a fork-branch `DisputeArmed`. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**Disputant**
: A quorum member who has appended `DisputeEnter` and `DisputeArmed` to their fork of the disputed ledger. The operator is structurally barred; disputants = (Q − 1).

**`DisputeYield`**
: The operation a losing disputant appends to their fork. Tombstones the branch.

**Durable event**
: A Nostr event whose kind is in a range relays are expected to retain indefinitely (1000-9999, 30000-39999). Contrast ephemeral. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

## E

**Economic deterrence**
: The protocol's central security argument: configure existing primitives so that misbehavior costs the operator more than it could earn. See [Chapter 1: Introduction](01-introduction.md).

**Embedding (`ProofEmbedding`)**
: The placement of a fraud-proof hash into a ledger's update to anchor it temporally. Direct embedding (into the accused ledger), one-hop (into a member's ledger), or further. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**Ephemeral event**
: A Nostr event whose kind is in the 20000-29999 range. Relays drop these after seconds. Used for request/response traffic. Contrast durable.

**Equivocation**
: The attack of signing two different valid updates at the same `(sequence_number, previous_hash)` with different `content_hash`. See [Chapter 14: Equivocation Defense](14-equivocation-defense.md).

**Escalation**
: A wallet's act of routing an ignored request to a quorum member who anchors it on their own ledger. See delivery escalation.

**Expired (`QuorumState`)**
: The state a quorum enters if `quorum_expiry` passes without a fresh `QuorumBegin`. The chain becomes non-conforming and any member can dispute.

## F

**`FeeChange`**
: The operation that announces a future fee change for a deposit. Bounded by the deposit's fee-change governance: `fee_change_after_blocks`, `fee_change_notice_blocks`, `fee_change_limit_bps`. See [Chapter 10: Fees and Time Obligations](10-fees-and-time.md).

**`FeeCollect`**
: The operation that debits accrued custody fee from a deposit's balance into `fees_accumulated`.

**Fee schedule (`FeeStructure`)**
: The pair `(annualized_msats, annualized_bps, frequency_blocks)` controlling periodic custody fees on a deposit. Per-deposit. Plus `TransferFeeSchedule` for per-transfer fees.

**`fees_accumulated`**
: The running monotonic counter on `LedgerState` of all fees the operator has accrued on this ledger. Substrate for future member-compensation payouts.

**Fork (fork branch)**
: A new chain rooted at the last conforming sequence of a disputed ledger. Created by each disputant; the on-chain lottery selects one as canonical. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**Fraud proof (`FraudProof`)**
: Cryptographic evidence that a ledger contains an event that should not have been there or omits an event that should have been. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**Fraud broadcast (`FraudBroadcast`)**
: The on-the-wire shape of a fraud proof: the proof, an embedding, and a causal chain. Published as Nostr `Kind:9101`.

**`FraudProofType`**
: The enum of fraud-proof variants: `UncreditedOnchainPayment`, `UncreditedLightningPayment`, `StaleCosignature`, `InactiveQuorumMember`, `NonConformingUpdate` (placeholder).

## G

**Gap-fill**
: The receiver's act of fetching missing prior updates from a relay when a new update's `previous_hash` is not on the local chain.

**Genesis block**
: The Bitcoin block height at which a ledger was opened. Hashed into `ledger_id`.

**Gift wrap**
: The NIP-59-shaped envelope for sensitive requests: a rumor, sealed by the real sender, wrapped by a throwaway key. Used for admin commands and Lightning verification. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

## H

**`HASH160`**
: `RIPEMD160(SHA256(x))`. Used for the lottery commitment hash. Output is 20 bytes; reveals nothing about preimage length.

**Hash-locked contract / HTLC**
: A payment that resolves on disclosure of a preimage. The atomicity primitive Lightning, couriers, and (some) recovery-pipeline branches all share. See [Chapter 3: Background](03-background.md).

**Hash-to-curve**
: The construction used by bLSAG to derive an auxiliary base point from a public key. See [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md).

## I

**Idempotency**
: The protocol property that a re-broadcast of the same update is a no-op. The `(sequence_number, content_hash)` dedup in the actor's apply path enforces this.

**`InactiveQuorumMember`**
: A fraud-proof variant slashing a member who was online during the response window after a fraud proof but did not act. Their *own* ledger's collateral is at stake. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**`InvoiceCredit`**
: The operation crediting a deposit with the proceeds of a received Lightning (or offer-mediated on-chain) payment. Indexed by `payment_hash`.

**`InvoiceFail`**
: The operation releasing an `InvoiceLock` without a preimage. The payment failed; the deposit is charged the fixed transfer-fee.

**`InvoiceFulfill`**
: The operation closing an `InvoiceLock` with a preimage that hashes to the locked `payment_id`. Successful payment.

**`InvoiceLock`**
: The operation locking deposit funds for an outgoing Lightning payment. Carries a witness satisfying the deposit's descriptor.

## K

**Kind (Nostr)**
: A 16-bit integer classifying a Nostr event. Range encodes persistence: 1000-9999 durable, 20000-29999 ephemeral, 30000-39999 NIP-33 replaceable. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**Kind 9100 / 9101 / 9103 / 9104 / 9106**
: Ledger update / fraud broadcast / dispute / recovery agreement / custody-lottery reveal. The durable protocol kinds.

**Kind 20101 / 20102**
: Ledger request / ledger response. Ephemeral, the wallet-to-operator transport.

**Kind 39100 / 39102**
: Ledger advertisement / courier advertisement. NIP-33 replaceable; the discovery layer.

## L

**Ledger**
: An append-only chain of signed updates owned by a single operator at a time. The protocol's unit of custody. Identified by a 32-byte `ledger_id`. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Ledger advertisement**
: The discovery event (Kind 39100) operators publish naming themselves, their fees, their reserves, and their preferred relay. NIP-33 replaceable.

**`ledger_id`**
: The 32-byte identifier of a ledger: `SHA256(operator_pubkey || reserves_id || genesis_block_le)`. Fixed for the life of the ledger; survives custody transfer.

**`LedgerOpen`**
: The first operation on a ledger (sequence 0). Establishes ledger identity.

**`LedgerOperation`**
: The enum of every state-machine transition the protocol supports. The protocol surface. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**`LedgerState`**
: The in-memory representation of everything a ledger's chain has accumulated: deposits, reserves, collateral, quorum, dispute state, accumulated fees.

**Lightning bridging**
: The operator routing Lightning payments on behalf of deposits via their own LN node. See [Chapter 9: Payment Channels](09-payment-channels.md).

**Locked balance**
: A deposit's portion committed to a pending transfer, invoice, or withdrawal. `available_balance = balance - locked_balance`.

**Lottery output**
: The Taproot output the confiscation transaction creates, whose tapscript tree contains the primary lottery-claim leaf, partial-reveal leaves (at N≥11), and the recovery long-tail. See [Chapter 5: On-Chain Transactions](05-onchain-transactions.md), [Chapter 13: Custody Lottery](13-custody-lottery.md).

## M

**`MAX_DISPUTANTS = 15`**
: The on-chain script's hard cap on disputant count. Set by witness sizes and bond economics. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**`MAX_QUORUM_SIZE_POLICY = 7`** (with `VALID_QUORUM_SIZES = {3, 5, 7}`)
: The current policy cap on `Q`, the cosigner count. The operator is *not* counted in `Q`. Restricted to odd values 3-7 inclusive. One-line constant change to lift or extend the allowed set; below the script's 15-disputant capacity.

**`max_transfer_timeout_blocks`**
: The quorum-negotiated upper bound on `TransferLock` timeouts. Default 1008 blocks (~1 week).

**Member**
: See quorum member.

**`member_ledger_hash`**
: The 32-byte hash of the cosigner's *own* ledger tip at cosign time, embedded in every `CosignEntry`. The atom of the causal-ordering web. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**Membership / `membership_until`**
: The expiry block height at which a member's commitment to a quorum ends. The shortest member's value is the quorum's `quorum_expiry`.

**Miniscript / miniscript descriptor**
: The script-policy language used for deposit spending conditions. Single-key (`pk(...)`), multisig (`multi(k, ...)`), conditional (`and()`, `or()`, `sha256()`, `after()`). See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**MuSig**
: The Schnorr-signature aggregation protocol. Used for the operator + quorum cooperative spend path on the reserves UTXO. Distinct from off-chain cosignatures (which are not aggregated). See [Chapter 3: Background](03-background.md).

## N

**NIP-01 / NIP-04 / NIP-17 / NIP-33 / NIP-59 / NIP-78**
: Nostr Improvement Proposals. Define event shape, encryption, gift-wrap, replaceable events, and application-state storage. The protocol uses subsets and divergences.

**Nonce**
: The 32 random bytes the wallet supplies on every `TransferLock`. Also the canonical fraud-proof embedding slot. See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**`NonConformingUpdate`**
: A reserved fraud-proof variant for any update that violates `Ledger::checked_apply`. Currently a placeholder accept; not yet wired to slashing.

**Normal (`DisputeState`)**
: The default per-ledger state. Allows every operation except `DisputeAcquire`/`DisputeYield`. Fork-branches return to `Normal` only via `DisputeAcquire`.

**Nostr**
: The event-broadcast protocol the deposits protocol uses for off-chain transport. Described in [Chapter 3: Background](03-background.md) and [Chapter 6: Peer Messaging](06-peer-messaging.md).

**Nullifier**
: The unique tag a bLSAG ring signature emits to prevent double-signing while preserving signer anonymity. See [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md).

**NUMS point**
: A "nothing-up-my-sleeve" public key with no known discrete log. Used as the internal key on every reserves UTXO and lottery output, ensuring no key-path spend is possible. See [Chapter 5: On-Chain Transactions](05-onchain-transactions.md).

## O

**Offer**
: A per-deposit Bitcoin address derived under the operator's wallet, paired with a co-signed announcement binding it to the deposit. Gift-wrapped to the requesting wallet. See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**`OnchainCredit`**
: The operation crediting a deposit with confirmed on-chain funds (no offer issued).

**`OnchainFail`**
: The operation releasing an `OnchainLock` after a withdrawal fails to confirm.

**`OnchainFulfill`**
: The operation finalizing an `OnchainLock` after the spending TX has confirmed.

**`OnchainLock`**
: The operation locking deposit funds for an outgoing on-chain withdrawal.

**Operator**
: The active custodian of a ledger. Runs the daemon, holds the operator key, signs ledger updates, earns fees. Identity is per-ledger and rotates on `DisputeAcquire`. See [Chapter 2: Mental Model](02-mental-model.md).

**Operator signature**
: The 64-byte BIP-340 Schnorr signature on every signed update over `content_hash`.

## P

**`p`-tag** / **`d`-tag** / **`l`-tag** / **`n`-tag** / **`t`-tag** / **`i`-tag** / **`e`-tag**
: Nostr tag conventions. `p`: target pubkey. `d`: ledger ID prefix or NIP-33 replacement key. `l`: full ledger ID. `n`: sequence number. `t`: operation discriminant. `i`: deposit ID. `e`: referenced event ID. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**P2TR**
: Pay-to-Taproot. The output type every reserves UTXO and lottery output uses.

**`parent_pubkey`**
: The pubkey that signed the most recent update on a ledger. All subsequent updates must be signed by this same pubkey (except `DisputeEnter`).

**Partial-reveal**
: A lottery outcome where some disputants did not reveal their preimages within the CSV-72 window. Falls through to a partial-reveal leaf (one missing) or to the recovery long-tail. See [Chapter 13: Custody Lottery](13-custody-lottery.md).

**`payment_hash`**
: The SHA-256 of a Lightning preimage. The index for credit operations; what cosignatures are bound to.

**Pending transfer / pending invoice / pending withdrawal**
: In-flight operations on a ledger, awaiting completion or timeout. Tracked in `LedgerState`.

**Periodic interval**
: The daemon's polling cadence — 60s in production, 5s in fast-poll mode. The safety net behind event-driven wakeups. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**Predator (incentivized predator)**
: The whitepaper's framing for a quorum member: small steady income from cosigning, large windfall from inheriting the operator's ledger via the lottery. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**`PreQuorum`**
: The initial `QuorumState`. Operator-only signatures; no cosigning yet. Transitions to `Active` on first `QuorumBegin`.

**Preimage**
: The secret whose hash binds a hash-locked contract. Length-as-entropy in the custody lottery (17 to 16+N bytes); 32 bytes in Lightning HTLCs.

**`previous_hash`**
: The chain hash of the prior update in the chain. Each new update names this; the very first update sets it to `[0; 32]`.

**Punitive recovery**
: A recovery mode where the operator is provably dishonest. The full UTXO (reserves + collateral) goes to the lottery output; the winner inherits the deposit obligations and keeps the collateral. Contrast respectful recovery. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

## Q

**Q (quorum size)**
: The number of cosigners. The operator is *not* counted in `Q`. Valid `Q ∈ VALID_QUORUM_SIZES = {3, 5, 7}` (odd-only, ≥3 for redundancy, ≤`MAX_QUORUM_SIZE_POLICY = 7`). Disputants per dispute = `Q` exactly (every cosigner can dispute; the operator is barred from disputing their own ledger and was never in `Q`).

**Quorum**
: The set of operators who co-sign a particular ledger's updates. Each ledger has its own; membership is asymmetric (A's quorum can include B, but B's quorum need not include A). See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**Quorum member**
: An operator of *some other* ledger who has agreed to cosign A's updates. Validates updates, watches for fraud, participates in disputes. See [Chapter 2: Mental Model](02-mental-model.md).

**`QuorumAddMember`**
: The operation that stages a new member into `next_quorum_members`. Activated on the next `QuorumBegin`.

**`QuorumBegin`**
: The rotation event that promotes `next_quorum_members` to `quorum_members`, transitions `quorum_state` from `PreQuorum` to `Active`, and rotates the on-chain reserves UTXO. The heaviest operation in the protocol.

**`quorum_expiry`**
: The block height at which the active quorum's commitment ends. A new `QuorumBegin` must land before this.

**`QuorumJoin`**
: The operation a member appends to their *own* ledger when accepting membership in someone else's quorum. Has ratchet semantics on `membership_expires`.

**Quorum independence**
: The graph-theoretic property that an operator's multiple ledgers' quorums are not dominated by overlapping members. Compounds security per the simulation. Measured by metrics like `quorum-mincut`. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**`QuorumRemoveMember`**
: The operation that drops a member, immediate (no `QuorumBegin` needed for off-chain effect).

**`QuorumState`**
: The per-ledger quorum state-machine variable. `PreQuorum` | `Active` | `Expired`.

## R

**Recipient**
: The party whose deposit is the destination of a transfer. Distinct from depositor in the wallet sense — the recipient may not own the source deposit.

**Recovery agreement (Kind 9104)**
: A member's broadcast announcing their fork-branch hash. Lets disputants converge on a shared dispute state without explicit consensus.

**Recovery long-tail**
: The cascade of CSV-gated multisig leaves (144 / 1008 / 4032 / 8064 blocks) on the lottery output ensuring funds are eventually sweepable even if the lottery stalls. See [Chapter 13: Custody Lottery](13-custody-lottery.md).

**Recovery pipeline**
: The sequence of stages — detect, fork, enter, arm, lottery, acquire, cleanup — by which a fraud proof is converted into custody change. See [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md).

**Recovery quorum**
: Quorum members minus the disputants minus the disputed operator. The set that cosigns the confiscation transaction.

**Relay**
: A Nostr server. Stores and serves signed events to filtered subscriptions. Not trusted; just a transport. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**Reserves**
: The deposit-capacity portion of the operator's UTXO. Total deposit balances cannot exceed this. Lives in the same Taproot output as collateral. See [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**Reserves rotation**
: The cooperative quorum spend that moves the reserves UTXO into a new P2TR output. Triggered by quorum churn or impending `quorum_expiry`. See [Chapter 5: On-Chain Transactions](05-onchain-transactions.md).

**Reserves UTXO**
: The single Bitcoin Taproot output anchoring a ledger. Holds reserves + collateral. Internal key is NUMS; spend paths are tiered script leaves.

**Respectful recovery**
: A recovery mode where the operator is unavailable but no fraud is proven. Reserves go to the lottery; collateral returns to the operator. Contrast punitive recovery.

**Ring signature**
: A signature scheme proving membership in a known set without revealing which member. The protocol uses bLSAG; see [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md).

## S

**Schnorr signature**
: The signature scheme for Taproot spends and protocol cosignatures. BIP-340. Linear, batch-verifiable, MuSig-aggregable. See [Chapter 3: Background](03-background.md).

**Self-pay**
: An operator's optimization where two deposits on the same ledger settle a Lightning invoice internally without LN routing. `InvoiceFulfill` with zero preimage + `InvoiceCredit` in one commit. See [Chapter 9: Payment Channels](09-payment-channels.md).

**Sequence number (`sequence`, `sequence_number`)**
: The monotonic u64 on every signed update. First update is sequence 0; each subsequent one is exactly one higher.

**`service_response_blocks`**
: The negotiated window after a `DeliveryEmbed` within which the operator must process the request. Default 72 (~12 hours). See [Chapter 15: Delivery Escalation](15-delivery-escalation.md).

**`SignedLedgerUpdate`**
: The shape of a single ledger update: operator id, ledger id, sequence, previous hash, message, block height, block hash, cosignatures, operator signature. The on-the-wire, on-disk, and in-memory representation. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Slashable**
: An obligation whose violation is provable as fraud and triggers the dispute pipeline. Contrast advisory.

**Slashing**
: The forfeiture of an operator's collateral via the recovery pipeline.

**Stage (`stage_operation`)**
: The first phase of the operator's two-phase commit. Validates against current state; produces a `StagedUpdate`; does *not* mutate the ledger.

**`StaleCosignature`**
: A fraud-proof variant accusing a member of producing a cosignature whose `member_ledger_hash` was already stale at sign time. The member's own ledger advanced past it before the operator's update was signed. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

## T

**Tag** (Nostr)
: An array attached to an event for indexing and addressing. Single-letter tags are server-filterable; multi-letter tags are client-only. See [Chapter 6: Peer Messaging](06-peer-messaging.md).

**`target_reserves`**
: The Bitcoin address a disputant nominates in `DisputeArmed` for the lottery prize.

**Taproot**
: The Bitcoin output type combining a key-path spend (cooperative, single Schnorr signature) with a script-path tree (`Tapscript` leaves revealed as needed). See [Chapter 3: Background](03-background.md).

**Tapscript / Tapscript leaf**
: A script committed inside a Taproot script tree. Revealed only when used; never reveals other leaves. The protocol's reserves and lottery scripts live as Tapscript leaves.

**Tier 0 / 1 / 2 / 3** (reserves UTXO script)
: The four progressively-looser-threshold, progressively-longer-CSV spend paths in the reserves Taproot tree: majority quorum (immediate, no operator); minority quorum (~1 week); operator solo (~2 weeks); anyone (~4 weeks). See [Chapter 5: On-Chain Transactions](05-onchain-transactions.md).

**Time obligation**
: An operation valid only after N blocks since a prior event. Catalogued in DEP-11. See [Chapter 10: Fees and Time Obligations](10-fees-and-time.md).

**Timeout (`timeout_height`)**
: The block height past which a `TransferLock` is eligible for `TransferFail`. Bounded by `max_transfer_timeout_blocks`.

**TLV** (Type-Length-Value)
: The BigSize-prefixed binary encoding (BOLT-1 compatible) used for `LedgerOperation` payloads. Field tags have specified numbers; sorted ascending; base64-ed into Nostr `content`. See [Chapter 4: Ledger State Model](04-ledger-state.md).

**Tombstoned (`DisputeState`)**
: A fork-branch state reached by `DisputeYield`. No further operations on this branch are valid.

**Transfer**
: A two-phase intra-ledger value movement: `TransferLock` then `TransferComplete` or `TransferFail`. See [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md).

**`TransferComplete`**
: The operation closing a `TransferLock` by satisfying its `completion_script`. Funds move; full fee accrues to the operator.

**`TransferFail`**
: The operation closing a `TransferLock` by timeout. Funds return to source; fixed fee accrues to the operator.

**`transfer_id`**
: The 32-byte deterministic identifier of a transfer: `SHA256(transfer_lock_signing_message(...))`.

**`TransferLock`**
: The operation locking source-deposit funds for a conditional transfer. Carries source, destination, amount, fee, completion script, timeout height, nonce, and witness.

**Trust assumption**
: The protocol's central security premise: at least one quorum member of any given ledger is honest. Not a majority. One. See [Chapter 2: Mental Model](02-mental-model.md), [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md).

**Two-phase commit**
: The operator's pattern of stage → cosign → commit. Validation precedes signing precedes application. See [Chapter 4: Ledger State Model](04-ledger-state.md).

## U

**`UncreditedLightningPayment`**
: A fraud-proof variant: a paid Lightning invoice whose payment hash never appears as `InvoiceCredit` on the operator's ledger. Requires the payer to surface the preimage. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**`UncreditedOnchainPayment`**
: A fraud-proof variant: a confirmed on-chain payment to a co-signed offer address that the operator never credited. Autonomously provable — no third-party preimage needed.

**Update**
: See `SignedLedgerUpdate`.

**UTXO**
: An unspent Bitcoin transaction output. The reserves UTXO is the single P2TR output anchoring a ledger.

## W

**Wallet**
: The depositor's client. Holds the keys authorizing spending from a deposit, speaks Nostr to relays, replays chains to track balance. Offline-tolerant. See [Chapter 2: Mental Model](02-mental-model.md).

**Web of causality**
: The whitepaper's term for the causal-ordering graph that emerges from cross-ledger cosignatures. Every member's `member_ledger_hash` folds into the operator's chain; every operator's chain folds back into the member's via reciprocal cosigning. See [Chapter 11: Fraud Proofs](11-fraud-proofs.md).

**Web of trust (WoT)**
: The graph of attested operator-to-operator endorsements wallets use as a trust anchor in discovery. Anonymous variants use ring signatures. See [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md).

**Witness**
: A stack of byte arrays satisfying a script (for transfers, descriptors, lottery claims). Verifies under the appropriate evaluator.

## Y

**Yield**
: See `DisputeYield`.
