# Appendix C: Error Codes and Conformance Violations

> **Audience**: developers, operators (debugging), integrators
> **Prereqs**: chapter 4 (state model), chapter 11 (fraud proofs)
> **DEPs**: DEP-02, DEP-06

This appendix is the catalogue of error conditions the protocol surfaces. There are five distinct layers, each with its own error vocabulary:

1. **Conformance violations** (`violation_type` strings) — what an *operator's chain* must not contain. These are the strings members report when refusing to cosign and that fraud-proof verifiers reproduce when a `NonConformingUpdate` broadcast is filed. The set is small, named, and stable — it is part of the wire surface.
2. **Validation rejections** — errors `validate_*` functions return *before* an operation is staged. These prevent a malformed operation from ever being signed; they are operator-internal.
3. **State machine errors** — errors `LedgerState::apply()` and `Ledger::commit_staged()` produce when an operation slips past pre-validation but cannot be applied (typically because some invariant only checkable against the post-state fails).
4. **Daemon-level errors** (`Error::*`) — high-level error categories the node surfaces over JSON-RPC and in logs. These wrap the lower-level errors with context (which RPC, which peer, which ledger).
5. **Recovery / dispute-pipeline errors** — errors specific to the long-tail confiscation path: the lottery, the on-chain TX build, the reveal/claim cleanup.

The first layer is the most important because conformance strings are *contracts between operators*. Members reject operators by these strings; fraud-proof verifiers reproduce the same checks; danger-mode tooling fabricates them by name (`deposits-node danger publish-invalid <reserves_id> <violation_type>`). If you change one of these strings, every downstream consumer breaks.

The remaining layers are looser. Validation messages are free-form English; daemon errors are wrapped Rust enums; recovery errors are mostly DepositsError variants augmented with context strings. They are stable to read but not stable to parse.

## 1. Conformance violations

Conformance violations are the named, stable subset. They live in two enums and one set of `violation_type` string literals:

- `deposits-protocol/src/error.rs:DepositsError::ProtocolViolation { violation_type, details }` — the wire-stable form. The string is what members and fraud verifiers compare against.
- `deposits-protocol/src/types/conformance.rs:ConformanceViolation` — a small structured enum returned by `LedgerState::check_conformance`. Variants: `InsufficientReserves`, `InvalidWitness`, `ProtocolRule`. This is the form witness verifiers produce; it gets rendered into a `violation_type` string for transport.
- `deposits-core/src/validation.rs:ConformanceViolation` — a richer enum used by the `LedgerConformanceValidator` for offline ledger audits (see `deposits-node ledger validate <ledger_id>` and chapter 22). It includes hash-chain / sequence / signature checks the protocol-layer enum doesn't.

The table below catalogs every `violation_type` string the protocol emits today, where it fires, and the fraud-proof type it triggers if it survives the operator's own filters and ends up signed onto the chain.

| `violation_type` string | When it fires | Source | Fraud type ([ch. 11](11-fraud-proofs.md)) |
|---|---|---|---|
| `duplicate_credit` | `InvoiceCredit` whose `payment_hash` is already in `credited_payments`. Each payment hash credits exactly once; a second credit is either a bookkeeping bug or an attempt to over-issue claims against the reserves. | `deposits-protocol/src/types/ledger_state.rs:294` | `UncreditedLightningPayment` (when the *missing* credit is provable) |
| `conformance` | Generic wrapper emitted by `LedgerState::check_and_apply` when any `ConformanceViolation` is observed. The `details` field contains the inner violation's `Display` text. Operators see this when their own apply-path refuses to advance. | `deposits-protocol/src/types/ledger_state.rs:665` | `NonConformingUpdate` |
| `invalid_message_hash` | A signing helper was given a message hash of unexpected length (not 32 bytes). Almost always indicates a serialization bug in caller code. | `deposits-core/src/signing.rs:38, 66, 177, 221, 247` | (rejected pre-broadcast) |
| `invalid_signature` | A 64-byte signature blob failed `Signature::from_slice`. Either the bytes are malformed or the operator signed with the wrong scheme. | `deposits-core/src/signing.rs:74, 255` | (rejected pre-broadcast) |
| `invalid_descriptor` | A descriptor string in a deposit, transfer, or rotation cannot be parsed by `deposits-core/src/descriptor.rs`. Caller passed an unsupported descriptor variant or hex-decoded a non-key. | `deposits-core/src/descriptor.rs:51, 57, 106` | (rejected pre-broadcast) |
| `custody_dispute_unauthorized` | A `DisputeArmed` operation appears on a ledger whose operator has not been disputed. Disputes are only valid on a *forked* branch; an operator producing one on their canonical chain is signaling fraud directly. See [chapter 12](12-recovery-pipeline.md). | `deposits-core/src/ledger.rs:320` | `NonConformingUpdate` |
| `invalid_signer` | The operator signature on a `SignedLedgerUpdate` does not match the ledger's `operator_id`. Either an impostor pushed an update or the operator key was rotated without ratchet. | `deposits-core/src/ledger.rs:333` | `NonConformingUpdate` |
| `invalid_signature` (apply path) | The operator's Schnorr signature failed verification. | `deposits-core/src/ledger.rs:362` | `NonConformingUpdate` |
| `hash_chain_break` | An update's `previous_hash` does not match the prior update's `content_hash`. The chain has been forked, replayed, or skipped. Detected during `apply_update`. | `deposits-core/src/ledger.rs:384, 504` | `NonConformingUpdate` |
| `dispute_state_violation` | A non-dispute operation arrived on a ledger whose `dispute_state` is not `None`, or a dispute operation arrived when no dispute is active. The ledger's dispute state machine forbids the transition (see [chapter 4](04-ledger-state.md), [chapter 12](12-recovery-pipeline.md)). | `deposits-core/src/ledger.rs:407, 1224` | `NonConformingUpdate` |
| `missing_cosignature` | An update that requires a cosignature (anything in `Active` quorum state except a small set of operator-only ops) arrived with `cosignatures.len() < required_threshold`. | `deposits-core/src/ledger.rs:423, 460` | `NonConformingUpdate` |
| `empty_quorum` | The ledger declares `Active` quorum state but `quorum_members` is empty — impossible by construction; only happens if state was tampered with. | `deposits-core/src/ledger.rs:450` | `NonConformingUpdate` |
| `custody_acquire_not_candidate` | A `CustodyAcquire` operation references a winner pubkey that was not among the `DisputeArmed` participants on the fork. See [chapter 13](13-custody-lottery.md). | `deposits-core/src/ledger.rs:550` | `NonConformingUpdate` |
| `custody_acquire_missing_claim` | A `CustodyAcquire` published before the on-chain confiscation TX was confirmed. The new custodian must point at a real chain anchor. | `deposits-core/src/ledger.rs:559` | `NonConformingUpdate` |
| `custody_yield_is_winner` | The lottery winner published `CustodyYield` instead of `CustodyAcquire`. Yielding is for the *losers*; the winner must take. | `deposits-core/src/ledger.rs:593` | `NonConformingUpdate` |
| `fee_change_violation` | A `DepositFeeChange` violates one of the negotiated guard rails: not enough blocks since open (`fee_change_after_blocks`), not enough notice (`fee_change_notice_blocks`), or change exceeds the limit (`fee_change_limit_bps`). See [chapter 10](10-fees-and-time.md). | `deposits-core/src/ledger.rs:964, 1066` | `NonConformingUpdate` |
| `quorum_size_policy_exceeded` | `QuorumJoin` would push the quorum past `MAX_QUORUM_SIZE_POLICY = 8`. Members reject the join; operators reject their own attempt to commit it. The cap can be raised in code; the script supports up to 15. | `deposits-core/src/ledger.rs:1243` | `NonConformingUpdate` |
| `quorum_join_wrong_role` | A `QuorumJoin` arrives in a state that doesn't expect it (e.g., `quorum_state == Active` and the joiner is already a member). | `deposits-core/src/ledger.rs:1301` | `NonConformingUpdate` |
| `quorum_join_ratchet` | Quorum membership ratcheting was violated — a member appeared/disappeared without the corresponding `QuorumJoin` / `QuorumLeave` op. Membership only changes through ratcheted ops. | `deposits-core/src/ledger.rs:1317` | `NonConformingUpdate` |
| `custody_armed_no_quorum` | `DisputeArmed` arrived on a fork that has no quorum members. Without a quorum there is no one to dispute *against*. | `deposits-core/src/ledger.rs:1330` | `NonConformingUpdate` |
| `custody_acquire_no_claim` | `CustodyAcquire` carries no `claim_outpoint` referencing the on-chain confiscation. | `deposits-core/src/ledger.rs:1343` | `NonConformingUpdate` |
| `duplicate_deposit` | `DepositAdd` for a `deposit_id` that already exists. The hash is descriptor-derived; either the wallet reused the same descriptor (it shouldn't) or the operator has a stale state copy. | `deposits-core/src/ledger.rs:1509` | `NonConformingUpdate` |
| `ledger_close_with_deposits` | `LedgerClose` while the ledger still has outstanding deposit balances or locked funds. The operator must zero out before closing. | `deposits-core/src/ledger.rs:1538` | `NonConformingUpdate` |
| `ledger_hash_mismatch` | The advertised `chain_tip_hash` of an imported ledger does not match the hash recomputed from the updates. Used by `deposits-tools` for offline audits — the daemon never produces this, only consumes it. | `deposits-tools/tests/ledger_hash_test.rs:151` | (offline audit) |
| `missing_ledger_hash` | An imported ledger has no chain-tip hash to compare against. Same audit context as above. | `deposits-tools/tests/ledger_hash_test.rs:164` | (offline audit) |

The danger-mode CLI (`deposits-node danger publish-invalid <reserves_id> <violation_type>`) currently fabricates three of these by name: `invalid-hash`, `skip-sequence`, and `replay`. The first maps to `hash_chain_break`; the second produces a `sequence_mismatch` (which the `DepositsError::SequenceMismatch` variant covers but is not in the `violation_type` namespace yet); the third forges a duplicate update, which an honest peer rejects via signature/sequence checks before any conformance string is involved.

### Higher-level conformance shapes

Beyond the wire-string namespace, two structured enums describe conformance state. These are the inputs to `NonConformingUpdate` proof verification (chapter 11) and to the offline `LedgerConformanceValidator` (chapter 22).

`deposits-protocol::ConformanceViolation` (the apply-path shape):

| Variant | Fields | Meaning |
|---|---|---|
| `InsufficientReserves` | `reserves`, `obligations` | After a credit op, total deposit balances exceed the operator's declared reserves. The flagship reserve breach; this is the conformance check that anchors the `over_promised_reserves` concept. See [chapter 7](07-quorum-and-collateral.md). |
| `InvalidWitness` | `operation: &'static str`, `detail: String` | A descriptor witness on `InvoiceLock` / `InvoiceFulfill` / `OnchainLock` / `TransferLock` / `DepositKeyRotate` failed to satisfy the deposit's miniscript descriptor, or a preimage didn't match a payment hash. The `operation` field names which op carried the bad witness. |
| `ProtocolRule` | `rule: &'static str`, `detail: String` | A rule with a static name fired. Currently unused at the protocol layer but reserved for future per-rule conformance hooks. |

`deposits-core::ConformanceViolation` (the offline-audit shape, used by `LedgerConformanceValidator`):

| Variant | Meaning |
|---|---|
| `BrokenHashChain` | A replayed update's hash does not chain. |
| `InvalidSignature` | A replayed update's operator signature failed verification. |
| `SequenceOutOfOrder` | Sequence numbers in the imported log are not monotonic. |
| `OperationFailed` | Replaying an operation against the running state returned an error. |
| `InsufficientReserves` | Same shape as the protocol layer; reserves don't cover total deposits. |
| `InsufficientCollateral` | Total collateral pledged by quorum members is below 100% of obligations. See [chapter 7](07-quorum-and-collateral.md). |
| `StateHashMismatch` | The recomputed final-state hash does not match the advertised chain tip. |
| `OperatorMismatch` | The operator pubkey on an update does not match the declared ledger operator. |
| `UncreditedPayment` | A payment was settled (preimage revealed) but no `InvoiceCredit` followed within the operator's own ledger. The smoking gun for `UncreditedLightningPayment` proofs. |

The set of strings `over_promised_reserves`, `fee_underflow`, `sequence_gap`, and `chain_break` that appear in operator-facing documentation are **not** present in code as `violation_type` literals. They are conceptual labels for groups of the structured violations above:

- "over_promised_reserves" → `ConformanceViolation::InsufficientReserves` and the apply-path `InsufficientReserves` `DepositsError`.
- "fee_underflow" → a `fee_change_violation` whose `details` indicate the new fee is lower than the negotiated floor.
- "sequence_gap" / "chain_break" → `hash_chain_break` is the wire string; `chain_break` appears as a metric label (`metrics::record_gap_fill("chain_break")` in `deposits-node/src/node/main_loop.rs:1514`); `SequenceMismatch` is the corresponding `DepositsError`. There is no separate `sequence_gap` `violation_type` today.

If a future change wants to expose these as first-class violation strings, it should add them in `LedgerState::apply` with the same shape as the existing entries.

## 2. Validation rejections

`deposits-core/src/operation_validation.rs` exposes ~20 `validate_*` functions, each returning `Result<(), String>`. They run *before* `apply_operation` and are pure — no I/O, no logging. The caller (a node, a CLI command, a test) checks them and refuses to stage if any fail. The strings are free-form English meant for a human reader; they are not stable API.

The full set of validators and what each checks:

**Reserves**

- `validate_reserves_add(initial_amount)` — rejects amounts below `MIN_RESERVES_OUTPUT_SATS` (economically unspendable) or above `MAX_RESERVES_OUTPUT_SATS`.

**Payments (Lightning)**

- `validate_credit_payment(ledger, deposit_pubkey, amount, payment_hash)` — checks deposit exists, amount is positive, amount ≤ 100 000 000 sats per credit, payment hash is not all-same-byte, total deposits stay within reserves, and (in `Active` quorum) within declared collateral.
- `validate_payment_lock(ledger, deposit_pubkey, amount, payment_id, signature)` / `validate_payment_lock_by_id(...)` — deposit exists, available balance suffices, amount > 0, scriptpubkey signature or descriptor witness validates against the deposit's authorization.
- `validate_payment_fulfill(...)` / `validate_payment_fulfill_by_id(...)` — amount > 0, signature valid, `sha256(preimage) == payment_id`.
- `validate_payment_fail(amount)` — amount > 0.
- `validate_cosign_invoice(ledger, assigned_deposit, amount, invoice_id, payment_hash)` — deposit exists, amount > 0 and ≤ 1 BTC (in msat), invoice ID non-empty, payment hash not all-same-byte, total deposits stay within reserves and collateral.

**Fees**

- `validate_fee_minimum(proposed, min_annual_bps, min_fixed_per_period)` — proposed structure meets operator minimums.
- `validate_fee_collect(...)` / `validate_fee_collect_by_id(...)` — deposit exists, sufficient available balance, current block ≥ `last_fee_assessment + frequency_blocks`.
- `validate_fee_change(...)` / `validate_fee_change_by_id(...)` / `validate_deposit_fee_change(ledger, deposit_id, new_fees, effective_block, current_block)` — full negotiated guard rail check (`fee_change_after_blocks`, `fee_change_notice_blocks`, `fee_change_limit_bps`). See [chapter 10](10-fees-and-time.md).

**Deposits**

- `validate_deposit_add(...)` / `validate_deposit_add_by_id(...)` — deposit doesn't already exist, pubkey not all zeros, fees valid (`frequency_blocks > 0`, `annualized_bps ≤ MAX_FEE_RATE_BPS = 10000`).
- `validate_deposit_close(...)` / `validate_deposit_close_by_id(...)` — deposit exists, balance is zero, locked balance is zero.
- `validate_deposit_key_rotate(ledger, deposit_id, new_descriptor, witness)` — deposit exists, witness satisfies the *current* descriptor (proof of possession), new descriptor non-empty.

**Withdrawals & transfers**

- `validate_onchain_lock_by_id(ledger, deposit_id, amount, fee_sats, destination_address, withdrawal_id, witness)` — deposit exists, available balance ≥ amount + fee, amount > 0, destination non-empty, witness valid against descriptor.
- `validate_transfer_lock(ledger, source_deposit_id, destination_deposit_id, nonce, amount, fee, completion_script, timeout_height, transfer_id, witness)` — source exists, amount > 0, available balance ≥ amount + fee, `transfer_id` matches the recomputed signing message, witness valid.
- `validate_transfer_complete(ledger, transfer_id, script_witness)` — pending transfer exists, script witness satisfies the completion script.
- `validate_transfer_timeout(ledger, transfer_id, current_block_height)` — pending transfer exists, current block ≥ `timeout_height`.

**Ledger lifecycle**

- `validate_ledger_close(ledger)` — total deposit balance is zero, total locked balance is zero. Note that `LedgerClose` also has a conformance check at apply time that produces `ledger_close_with_deposits` if a malformed close slips through.

A validation rejection means the caller should not commit. The right response is to bubble the error up to the user (CLI prints the string, JSON-RPC returns it as `error.message`) and let them fix the input. None of these are slashable on their own — the operator caught themselves.

## 3. State machine errors

`Ledger::commit_staged` and `LedgerState::apply` produce errors when an operation slipped past pre-validation but cannot be applied. Most of them are typed `DepositsError` variants from `deposits-protocol/src/error.rs`:

| Variant | When it fires |
|---|---|
| `InsufficientReserves { required, available }` | Apply-path reserve check. Same condition as the conformance violation but observed before the update gets signed. |
| `ReservesOutputNotFound(s)` | A reserves UTXO referenced for removal doesn't exist in the ledger's UTXO set. |
| `InvalidReservesDecrease(s)` | Decreasing reserves below outstanding obligations or by an unsigned operation. |
| `InvalidReserveAmount` | Proposed reserves amount is zero or otherwise non-spendable. |
| `NonZeroBalance { balance }` | `DepositClose` on a deposit with `balance > 0`. |
| `OutstandingInvoices { count }` | `DepositClose` on a deposit with locked invoices. |
| `InsufficientDepositBalance { available, required }` | Apply-path balance check on outbound payments, transfers, withdrawals. |
| `DepositNotFound`, `DepositAlreadyExists` | Self-explanatory; the apply-path equivalents of the validator check. |
| `InsufficientBalance` | Generic balance error (used by older paths; the typed variants above are preferred). |
| `UnknownPayment`, `PaymentAmountMismatch`, `PaymentNotLocked` | Payment-state-machine misorderings: fulfilling a non-locked payment, mismatched amounts, etc. |
| `LedgerAlreadyExists`, `LedgerNotFound`, `LedgerNotInitialized`, `LedgerIdMismatch` | Ledger-lookup errors. |
| `HandshakeInProgress`, `NoActiveHandshake`, `HandshakeRejected` | DEP-04 quorum-handshake state errors. |
| `PartnerNotFound`, `InvalidPartner`, `QuorumMemberAlreadyExists` | Quorum-membership lookup errors. |
| `InsufficientCollateral { required, available, missing_attestations }` | The set of partners whose attestations would be needed to close the gap; emitted when the operator tries to credit beyond pledged collateral. See [chapter 7](07-quorum-and-collateral.md). |
| `InsufficientQuorumMembers { operator_ledgers, partner_ledgers }` | Not enough active quorum members to meet threshold. |
| `InvalidChannelState` | Lightning channel state inconsistent with the operation. |
| `InvalidSecretKey`, `InvalidPublicKey`, `InvalidSignature` | Cryptographic primitives failed parsing or verification. |
| `InvalidMessage { reason }` | A wire message failed structural validation (TLV, lengths). |
| `ProtocolViolation { violation_type, details }` | The big one — see Section 1 above. |
| `PersistenceFailed { reason }`, `AuditQueueFull`, `SerializationError` | Storage-layer errors. |
| `FeeAssessmentFailed { reason }`, `AuditFailed { reason }`, `CosigningFailed { reason }` | Higher-level operation failures wrapping more specific causes. |
| `InvalidAddress(s)`, `InvalidAmount(s)`, `InvalidTimeout(s)` | Parser errors on user input. |
| `ProposalNotFound(s)`, `InvalidState(s)`, `InsufficientFunds(s)` | State-machine errors for offer/proposal flows. |
| `CodecError(s)` | TLV codec failure (auto-converted from `messages::CodecError`). |
| `HashMismatch { expected, actual }` | A hash provided by a peer doesn't match the locally recomputed value. Most commonly a chain-tip hash advertised in a Nostr event versus the recomputed `content_hash`. |
| `SequenceMismatch { expected, actual }` | Update sequence is not the next expected. The protocol-layer counterpart of the metric `chain_break`. |
| `BroadcastFailed(s)` | Transaction broadcast to bitcoind/electrs returned an error. |

`LedgerState::apply` returns `DepositsError`; it is the same enum used everywhere else, so callers don't have to translate. The wire-stable subset is `ProtocolViolation`; the rest are operational. See [chapter 4](04-ledger-state.md) for how `apply` and `check_and_apply` interact.

## 4. Daemon-level errors

`deposits-node/src/error.rs:Error` is the daemon's surface error. RPC handlers return it; the CLI prints it. The variants:

| Variant | Wraps | Typical cause |
|---|---|---|
| `Wallet(String)` | BDK / wallet errors | Output not found, fee too low, descriptor parse fail, RPC-server unreachable. |
| `Nostr(String)` | rust-nostr-sdk errors | Relay disconnect, publish timeout, event decode fail. See the [nostr publish-confirm note](#) — confirming a publish requires a separate client because cached events return immediately. |
| `LedgerNotFound { operator, partner }` | (none) | RPC asked for a ledger by `(operator, partner)` and no match exists. |
| `Handler(HandlerError)` | `deposits-core::HandlerError` | One of `ValidationFailed`, `LedgerNotFound`, `InvalidState`, `Internal` from the protocol-handler layer. |
| `Serialization(String)` | serde / TLV errors | JSON-RPC payload didn't deserialize. |
| `InvalidState(String)` | (none) | The daemon is in a state that can't service the request (e.g., reserves not yet created, quorum still forming). |
| `NoReserves` | (none) | RPC requires reserves; user has not run `reserves` yet. |
| `Protocol(String)` | (none) | Wraps a string returned from a deeper call — typically a `DepositsError` rendered with `to_string()`. The catch-all when a typed conversion isn't available. |
| `OfferNotFound` | (none) | `InvoiceCosign` / `DepositOpen` flow asked for an offer ID that has expired or never existed. |

`HandlerError` (defined in `deposits-protocol/src/error.rs`, used throughout `deposits-core` handlers) has four variants — `ValidationFailed`, `LedgerNotFound { operator, reserves_id }`, `InvalidState`, `Internal` — all carrying a `String`. It is the protocol-handler's flatter error type, kept LDK-agnostic.

The two conventions to remember:

- The daemon converts most `DepositsError` instances into `Error::Protocol(e.to_string())`. This loses the type tag but preserves the `Display` text. RPC clients should match on substrings or upgrade to a richer error contract if they need stronger discrimination.
- `Error::LedgerNotFound` exists at *both* the daemon and protocol layers with subtly different field names (`partner` vs `reserves_id`). The daemon variant is what crosses the JSON-RPC boundary; the protocol variant is internal.

## 5. Recovery / dispute-pipeline errors

The dispute-fork-arm-lottery path (chapters [12](12-recovery-pipeline.md), [13](13-custody-lottery.md)) introduces error conditions specific to long-tail recovery. These appear primarily in `deposits-node/src/node/dispute.rs`, `deposits-node/src/node_cli/recovery.rs`, and three `DepositsError` variants:

**`DepositsError::RecoveryQuorumUnreachable { n_quorum, n_disputants, t_emergency }`**
: The recovery quorum is too small to ever satisfy the long-tail recovery script's threshold. Without `t_emergency` non-disputing signers, a stalled lottery cannot be resolved on-chain. Fires in `tapscript_reserves.rs:797` when constructing the confiscation script. Response: the operator must rebuild the quorum to a larger size before the lottery can be re-armed. See [chapter 13](13-custody-lottery.md).

**`DepositsError::LotteryNotEconomical { disputed_value, min_required }`**
: Disputed value is less than 5× the estimated on-chain claim fee. Below this floor, an honest disputant rationally walks away rather than pays the fee, so the lottery cannot be relied on. The threshold is enforced at construction time so a doomed dispute is never armed. Source: `tapscript_reserves.rs:815`.

**`DepositsError::InsufficientBondRatio { n, actual, required, numerator, denominator }`**
: A disputant's posted bond is below the per-regime ratio required to keep defection irrational at the current disputant count. Each `n` (1..=Q-1) has its own bond floor; falling below it would let a colluding defector cheaper-than-honest. Source: `tapscript_reserves.rs:833`. Note: as of phase 5e of the lottery rollout, this check is *not* enforced as a gate — a simpler `MAX_QUORUM_SIZE_POLICY = 8` cap replaces it operationally — but the variant is retained for offline audit and for future per-regime tightening.

Beyond these typed variants, the dispute pipeline produces `Error::Protocol(...)` strings at several junctures:

- **"Need at least 2 DisputeArmed participants, found N"** — `recovery.rs:2425`. Confiscation can't proceed with fewer than two entropy-providing participants. Either run `recovery arm` on more peers, or wait for them to arm themselves.
- **"No DisputeArmed participants found"** — `dispute.rs:518`, `recovery.rs:1861, 3036`. The fork branch has no `DisputeArmed` ops yet. The pipeline blocks here until at least one arrives. Often a sign that auto-confiscation tripped on a ledger that was never actually disputed.
- **"You haven't published DisputeArmed yet. Run 'recovery arm' first."** — `recovery.rs:1866`. The local node hasn't armed itself; it cannot drive confiscation without its own commitment in the entropy pool.
- **"Could not find our DisputeArmed"** — `dispute.rs:523`, `recovery.rs:883, 3401`. The local daemon's own armed update is missing from its branch. Indicates a sync gap with the relay; re-fetching the ledger usually resolves it.
- **"Failed to append DisputeArmed to fork: {e}"** — `dispute.rs:227`. The auto-arm path could not append. The wrapped error names the root cause (often a state-machine error from section 3).
- **"No unspent UTXO found at lottery address. Was confiscation transaction confirmed?"** — `recovery.rs:3278`. The reveal phase can't find the on-chain output it expects to claim. Usually means the confiscation TX is unconfirmed or was double-spent.
- **"Already have DisputeArmed on fork"** (info-level, not an error) — `dispute.rs:190`. The auto-arm path noticed it already armed and exits silently. Idempotency, not a fault.

The dispute pipeline runs on a periodic interval ([dispute_periodic_interval note](#)), and the `auto_confiscate` loop (`dispute.rs:884`) treats most of the above as transient — it logs and retries on the next tick. Only the typed `DepositsError` variants are hard failures that surface to the CLI.

## Cross-references

- `violation_type` strings are wire-stable; the conformance enum types are source-stable. Treat them as a public API surface.
- Validation messages, daemon `Error::*` strings, and recovery-pipeline strings are not stable. Match on `violation_type` strings, on `DepositsError` variants by `match`, or on `Error::*` enum variants — never on free-form text.
- The fraud-proof types (`FraudProofType` in `deposits-protocol/src/fraud.rs`) cross-link the conformance violations to slashing outcomes; see [chapter 11](11-fraud-proofs.md) for which evidence shapes prove which violations.
- The danger-mode tooling (`deposits-node danger publish-invalid`) and the conformance fuzzer (`deposits-tools/fuzz/fuzz_protocol.rs`) exercise the conformance path; see [chapter 22](22-testing-and-fuzzing.md).
- The full state model that hosts these errors is in [chapter 4](04-ledger-state.md); the dispute and lottery pipelines that produce the recovery errors are [chapter 12](12-recovery-pipeline.md) and [chapter 13](13-custody-lottery.md).
