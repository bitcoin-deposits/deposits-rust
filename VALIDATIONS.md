# VALIDATIONS

A snapshot of where every protocol rule lives in the codebase. **Current state only** — this is a map, not a plan.

## The four enforcement layers

A rule lives in exactly one of these layers (sometimes mirrored across two for friendlier errors). When debugging "why was this update accepted/rejected?", check them in order:

| # | Layer | Where | Effect |
|---|---|---|---|
| 1 | **State-machine reject** | `LedgerState::apply` (`deposits-protocol/src/types/ledger_state.rs`) | Hard `Err` from `apply`. Every replay everywhere enforces it. A malicious operator cannot get an honest peer to accept the update by any means. |
| 2 | **Incoming-update gate** | `Ledger::validate_incoming_update` (`deposits-core/src/ledger.rs`) | Hard `Err` before `apply` is called. Runs on every received update. Same effective coverage as Layer 1 for authenticity / chain shape, but gated on the `Ledger` wrapper rather than the raw state. |
| 3 | **Conformance** | `LedgerState::check_conformance` → `ConformanceViolation` | Returns violations rather than rejecting. **Two consumers**: operator's own commit path (`Ledger::checked_apply` → refuses to publish) and the fraud-proof verifiers (used as evidence to dispute a published bad update). Honest cosigners refuse to co-sign updates whose post-state has any violation, so a non-conforming update never gathers majority and never reaches an honest peer's `apply`. |
| 4 | **Pre-broadcast policy** | `deposits-core/src/operation_validation.rs`, `deposits-core/src/message_validation.rs`, `deposits-core/src/validation.rs`, `deposits-node/src/node/**` | Operator-side checks before broadcast (CLI refuses, request handlers refuse). Bypassable by a malicious operator who hand-rolls a `LedgerOperation` and broadcasts it; the upstream defense for those is layers 1–3. |

"Bypass risk" below = "would honest peers accept this update if a malicious operator skipped the policy check and hand-rolled the operation themselves?"

---

## Reserves & accounting

| Rule | Layer | Source | Notes |
|---|---|---|---|
| `LedgerOpen` reserves amount in `[MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS]` | 4 | `operation_validation.rs:46-62` (`validate_reserves_add`) | Bypass risk **yes** — `apply` doesn't recheck. Caught only by the operator's own commit path and any cosigner that runs message validation. |
| Reserves amount > 0 | 4 | `validation.rs:168-173` | Same as above. |
| Reserves removal leaves enough to back deposits + max outstanding invoice | 4 | `validation.rs:330-342` | Bypass risk **yes**. |
| `total_deposits ≤ reserves_amount` after every credit | 3 | `ledger_state.rs:790-803` (`check_conformance`) | Reported as `ConformanceViolation::InsufficientReserves`. Operator's `check_and_apply` rejects; replay path stores it and the watcher emits a fraud proof. |
| `total_deposits ≤ collateral_amount` when quorum active | 4 | `operation_validation.rs:124-132` | Operator-side only; **not** mirrored in `check_conformance`. |
| `FeeCollect` amount ≤ deposit's `available_balance` | 4 | `validation.rs:214-228` | `apply` itself uses `saturating_sub`, so a too-large `FeeCollect` doesn't error — it just clamps. The validation check catches it pre-broadcast. |

---

## Quorum membership & ruleset

| Rule | Layer | Source | Notes |
|---|---|---|---|
| `QuorumAddMember` member is not already in `quorum_members` or `next_quorum_members` | 1 | `ledger_state.rs:534-542` | Silent dedup inside `apply`. |
| `QuorumAddMember.member_response` blob (when present): BIP-340 sig over digest, decoded `member_pubkey` matches outer `quorum_member`, every loose field equals the blob field | 4 | `operation_validation.rs::validate_quorum_add_member_blob` | Routed through `message_validation.rs` for the `QuorumAddMember` arm. Bypass risk **yes** — `apply` doesn't re-verify; a malicious operator could publish a blob with mismatched loose fields and the resulting state would still record their version. |
| `QuorumBegin` ruleset attestation: when `protocol_version != "legacy"`, every promoted member's `supported_rulesets` must include the chosen ruleset | 1 | `ledger_state.rs::apply` (`QuorumBegin` arm) | Skipped for `"legacy"` so existing pre-Q1 ledgers stay valid. Recently moved here from operator-side policy. |
| Operator-side equivalent of the ruleset attestation, for friendlier errors before cosign round | 4 | `node/ledger_queries.rs::rotate_reserves_to_quorum` | Mirror of layer 1 above. Both fire; layer 1 is authoritative. |
| `QuorumBegin.protocol_version` resolves to a known ruleset | 4 | `node/ledger_queries.rs::rotate_reserves_to_quorum` | `apply` accepts unknown names silently (defaults to `legacy` only for `None`); the operator-side check rejects unknown names. **Bypass risk yes** — a peer replaying a `QuorumBegin` with `protocol_version = Some("future-version")` will pin `active_ruleset_name = "future-version"` even though `lookup` returns `None`. Resolved later via `resolve_or_legacy` which silently falls back to legacy at read time. |
| First `QuorumBegin` (PreQuorum → Active) requires majority cosignatures from staged members | 2 | `ledger.rs:456-468` | Each cosignature is verified to be from a current `next_quorum_members` entry. |
| Post-`QuorumBegin`, every update except `DisputeEnter` carries a valid cosignature | 2 | `ledger.rs:417-430` | Hard reject. |
| `QuorumBegin` is non-empty (at least one staged member) | 2 | `ledger.rs:439-455` | Hard reject. `empty_quorum`. |
| `QuorumBegin.quorum_expiry ≤ min(membership_until)` over members | 4 | (search did not surface a hard check; documented intent) | **Status uncertain** — needs verification. |
| Cosigners refuse to co-sign past `quorum_expiry` | 3-ish | `ledger.rs:631-648` (`validate_for_cosign`) | Cosigner-side refusal. The operator alone can still publish post-expiry updates, but they won't gather signatures, so layer 2 rejects them via `missing_cosignature`. |
| `QuorumJoin` membership ratchet (expiry only increases) | 2 | incoming-update validation (`quorum_join_ratchet`) | Hard reject of regressions. |
| `QuorumJoin` is classified **value-moving** by `cosign_threshold::operation_class` | 3-ish | `deposits-protocol/src/cosign_threshold.rs` | Past a member's own `quorum_expiry`, cosigners on the *member's* ledger refuse to cosign new `QuorumJoin` updates (`post_expiry_cosign_refused`). Operationally this means: when the member's ledger has aged past its rotation window, they can't accept new quorum-add invitations from peers. The member must self-rescue (rotate their own ledger via `quorum repair`) first. Discovered during the `lifecycle_self_rescue` and `consent_request routing` investigations earlier; correct by design — a member with an expired ledger shouldn't make new commitments. |
| Cosign cascade tier classification per op (`Establishment` vs `ValueMoving` vs `Confiscation`) | 3-ish | `deposits-protocol/src/cosign_threshold.rs::operation_class` + `cosign_requirement` | `Establishment` (e.g. `QuorumBegin`) is cosignable post-expiry under the cltv-offset-v2 ruleset so the operator can self-rescue via `quorum repair`. `ValueMoving` (e.g. `InvoiceLock`, `OnchainLock`, `TransferLock`, `QuorumJoin`) is refused post-expiry. `Confiscation`-tier ops use a separate threshold cascade (DEP-06). |

---

## Chain integrity (signer, sequence, hash)

| Rule | Layer | Source | Notes |
|---|---|---|---|
| Update signed by `parent_pubkey` (or by current quorum member for `DisputeEnter`, or by dispute opener afterwards) | 2 | `ledger.rs:296-342` (`validate_update_signer`) | `invalid_signer`, `custody_dispute_unauthorized`. |
| Operator and cosigner signature bytes verify | 2 | `ledger.rs:359-364` | `update.verify_signatures(...)`. |
| `previous_hash` matches tip's chain hash | 2 | `ledger.rs:477-517` | Folded chain hash; truncation-safe. |
| Sequence number contiguity (gaps queue, not reject) | 2 | `ledger.rs:227-255` | Out-of-order updates park in `pending_updates`, flush when the gap fills. |
| Sequence number monotonicity | 1 | `ledger_state.rs::apply` (sequence is incremented unconditionally) | Implicit. |
| Dispute state allows the operation | 2 | `ledger.rs:405-413` (`dispute_state.allows_operation`) | `dispute_state_violation`. State machine: Normal → Disputed → Armed → (Normal\|Tombstoned). |

---

## Witness verification (cryptographic proofs)

All witnesses are verified inside `LedgerState::check_conformance` (layer 3). They appear as `ConformanceViolation::InvalidWitness` rather than `apply` errors:

| Operation | Source | What's checked |
|---|---|---|
| `InvoiceLock` | `ledger_state.rs:806-825` | Witness satisfies deposit descriptor over `invoice_lock_signing_message` |
| `InvoiceFulfill` | `ledger_state.rs:846-853` | `SHA256(preimage) == payment_id` |
| `OnchainLock` | `ledger_state.rs:855-877` | Witness satisfies deposit descriptor over `withdrawal_signing_message` |
| `TransferLock` | `ledger_state.rs:879-910` | Witness satisfies *source* descriptor over `transfer_lock_signing_message` |
| `DepositKeyRotate` | `ledger_state.rs:912-935` | Witness satisfies the **old** descriptor (read from `pre_state`), then `next.deposits[id].descriptor` is the new one |

These are layer 3 because the Bitcoin Deposits design uses them as *fraud evidence* — a published bad witness is the canonical case for a `NonConforming` fraud proof. `apply` deliberately does *not* reject; the watcher produces the proof.

### Signature scheme: **ECDSA**, not Schnorr

All witness signatures are verified by `Dep16Authorizer` (`deposits-core/src/dep16/authorizer.rs`) which is wired to `miniscript::calculus::EcdsaVerifier`. The wire format is 64-byte ECDSA compact, low-s-only (high-s rejected to close malleability — `secp.rs:54-61`).

The signing message is the dep-17 operation sighash: `operation_sighash(operation_preimage(op))`. The preimage commits to op_type + args + nonce + expiry + deposit_id, so a signature isn't replayable across deposits, op types, nonces, or expiries.

The wallet's `deposits_core::signing::sign_op` produces these via `secp.sign_ecdsa(...)`. Signer-side, daemon code that needs to mint a witness for an operator-owned deposit calls `signer.ecdsa_sign_sighash(SignContext::deposit(idx, ...), &sighash)`.

> **Bug history:** the admin `buffer-drain` handler (`request_handlers/admin.rs`) and the original drip auto-task both called `signer.bip340_sign(...)` instead — produced Schnorr sigs that `EcdsaVerifier::verify_signature` rejected with "witness does not satisfy deposit descriptor." Fixed in commits `4be74027` (drip) and `8a423b44` (buffer-drain). No test exercised buffer-drain past sig verification, so the bug stayed hidden in production code for some time.

X-only / BIP-340 / tr-key-path support is reserved for future descriptor variants — see the v1-scope note in `dep16/authorizer.rs:18-21`.

---

## Synthetic / operator-only operations (no Lightning oracle)

Cosigners verify that a ledger operation is *internally consistent* (signature checks out, hash chain matches, reserves invariant holds, conformance passes), but they have **no oracle** for whether the corresponding Lightning movement actually happened. This is what makes operator-owned "buffer" deposits and the liquidity-drip auto-task possible: they commit lightning-shaped ops with synthesized values and the protocol accepts them.

| Op | Synthetic field(s) | What cosigners verify | What they can't check |
|---|---|---|---|
| `InvoiceCredit` | `invoice_id` (any string), `payment_hash = sha256(invoice_id)` | Reserves invariant after credit | Whether LDK actually settled an invoice with this `payment_hash` |
| `InvoiceLock` + `InvoiceFulfill` (paired) | `payment_id = sha256(preimage)`, both fields locally-generated | Lock witness over the deposit descriptor (ECDSA, dep-17 sighash); fulfill's `SHA256(preimage) == payment_id` | Whether the lock was triggered by a real BOLT11 payment request, or whether the fulfill represents an actual settled Lightning hop |

**Operator-owned ("buffer") deposits.** Persisted in `<data_dir>/buffer_indices.json`. Each entry: `{ index: u32, ledger_id, deposit_pubkey }`. Index range starts at 1_000_000 to leave 0..1M for customer wallet keys derived from the same seed. Depositor key derives via `signer.pubkey_at(KeyPath::Deposit { index })` → `pk(<pubkey>)` descriptor.

Three admin/internal entry points (all in `node/request_handlers/admin.rs`):

| Method | Result |
|---|---|
| `internal_buffer_open(ledger?, index?) → BufferOpenOutcome` | Commits `DepositOpen` with `pk(<derived_pubkey>)`. Appends to `buffer_indices.json`. |
| `internal_buffer_fill(index, amount_msats) → new_balance` | Commits `InvoiceCredit` with a random `invoice_id` and the corresponding `payment_hash`. No LDK call. |
| `internal_buffer_drain(index, amount_msats) → new_balance` | Commits `InvoiceLock` + `InvoiceFulfill` paired: random preimage, ECDSA-signed lock witness via `signer.ecdsa_sign_sighash`. No LDK call. |

The matching admin RPC handlers (`process_admin_buffer_open_request` etc.) are thin auth + param-parse wrappers around these. The drip auto-task (`auto_drip_self_liquidity`) calls them too.

**Liquidity drip** (`deposits-node/src/operator_drips.rs` + `auto_tasks.rs::auto_drip_self_liquidity`). Operator-side defense against single-depositor liquidity exhaustion. Persists drip plans in `<data_dir>/operator_drips.json`; each plan references a `buffer_index` (allocated on first tick via `internal_buffer_open`). Periodic auto-task fills the buffer once (`internal_buffer_fill`) and then drains it `decrement_sats` per tick (`internal_buffer_drain`), optionally with `±interval_fuzz_sec` jitter rolled per-tick from `OsRng` so the schedule isn't predictable to a counterparty watching balances.

> **Implication:** an operator who can derive deposit keys can move arbitrary amounts of their *own* reserve capacity around without touching Lightning. This is by design — they're trading against themselves. The protocol's invariant (`total_obligations ≤ reserves`) still holds because the operator's own deposit balance is part of `total_obligations`. They can't use this to credit a *customer*'s deposit without that customer's witness, since `InvoiceCredit` doesn't have a witness gate (any `payment_hash` is accepted) but the customer doesn't see funds they could draw against unless the operator also credits *their* deposit — and that just adds to `total_obligations` against the same reserve pool.

---

## Deposit lifecycle

| Rule | Layer | Source | Notes |
|---|---|---|---|
| `DepositOpen` rejects duplicate `deposit_id` | 1 | `ledger_state.rs:307-309` | `DepositAlreadyExists`. |
| Every operation that names a `deposit_id` requires it to exist | 1 | scattered in `apply` | `DepositNotFound`. |
| `DepositClose` only when `balance == 0` | 1 | `ledger_state.rs:320-330` | `NonZeroBalance`. |
| Descriptor parses as miniscript | 4-ish | `descriptor.rs` (parsing surface in operator path); discovered at witness-verify time on replay | Bypass risk **yes for the parse step itself**; layer 3 catches operationally because witnesses won't satisfy a malformed descriptor. |
| `available_balance ≥ 0` invariant (`locked_balance ≤ balance`) | 4 (sanity) | `validation.rs:950-963` (`validate_business_rules`) | `apply` uses `saturating_sub` so this never *trips* in production; the check is a debug-time invariant. |
| `receive_requires_sig` deposits: receive endpoints (`make_invoice`, `make_offer`) require a witness over `SHA256(deposit_id || 0x00…)` | 4 | `node/request_handlers/deposits.rs:61-79` | Operator-side only. Bypass risk **yes** — a hostile operator can mint invoices for any deposit; honest cosigners' `validate_for_cosign` doesn't currently re-check this. |

---

## Payment / transfer flow

| Rule | Layer | Source | Notes |
|---|---|---|---|
| Duplicate `InvoiceCredit` (same `payment_hash`) | 1 | `ledger_state.rs:319-338` | `duplicate_credit`. Tracked in `state.credited_payments`. |
| `InvoiceLock` reduces available balance via `Deposit::lock` | 1 | `ledger_state.rs:380-382` | Implicit `InsufficientDepositBalance` if `available_balance < amount`. |
| `TransferLock`: `amount + fee ≤ available_balance` | 1 | `ledger_state.rs:671-676` | `InsufficientDepositBalance`. |
| `OnchainLock`: `amount + fee_sats ≤ available_balance` (both reserved) | 1 | `ledger_state.rs:454-474` | Both the destination amount and the miner fee budget are locked upfront. |
| `TransferFail`/`InvoiceFail`: fixed fee charged, variable fee zero | 1 | `ledger_state.rs:403-422`, `714-730` | Failure still pays the operator's fixed cost. |
| `OnchainFail`: fixed fee charged, but `amount + fee_sats` released back to balance | 1 | `ledger_state.rs:475-500` | Miner fee budget returns to the depositor since no tx was broadcast. |
| Transfer chain ordering (`TransferLock` → `TransferComplete`/`TransferFail`) | (search did not surface a hard ordering check beyond the pending lookup) | — | **Status uncertain**. |

---

## Dispute pipeline

| Rule | Layer | Source | Notes |
|---|---|---|---|
| `DisputeEnter` only by current quorum member (in Normal) | 2 | `ledger.rs:308-326` | `custody_dispute_unauthorized`. |
| `DisputeEnter` carries `last_valid_sequence`; recorded in `dispute_fork_sequence` | 1 | `ledger_state.rs:587-591` | State transition Normal → Disputed. |
| Dispute state transitions are one-way: Normal → Disputed → Armed → (Normal via Acquire \| Tombstoned via Yield) | 1 | `ledger_state.rs::apply` for each dispute op + `dispute_state.allows_operation` | Layer 2 gates which ops are valid in each state. |
| `DisputeAcquire.new_custodian` is one of the candidates that posted `DisputeArmed` | 4 (operator-side check) | `ledger.rs:537-563` | `custody_acquire_not_candidate`. |
| `DisputeAcquire.claim_txid` non-zero (proof of lottery spend) | 4 | `ledger.rs:557-561` | `custody_acquire_missing_claim`. |
| `DisputeYield` signer must NOT be the entropy-selected lottery winner | 4 | `ledger.rs:583-599` (`validate_custody_yield`) | `custody_yield_is_winner`. The winner is supposed to `DisputeAcquire`, not `DisputeYield`. |
| Quorum membership cannot be changed in Disputed/Armed/Tombstoned states | 2 | dispute state allows-list | Hard reject. |
| Confiscation tx output shape matches the fraud proof type | 2 | `request_handlers/custody.rs::verify_proposed_confiscation_tx` | Cosigner re-derives the expected outputs via `dispute::build_expected_confiscation_outputs` and compares to the operator's proposed `unsigned_tx` byte-for-byte (output count, values, scripts) before signing the sighash. **Punitive** = 1 output to lottery for full UTXO − fee. **Respectful** (currently only `QuorumExpired`) = 2 outputs: lottery for `max(obligations_sats, P2WSH_DUST_LIMIT_SATS)` and operator P2WPKH change for the rest − fee. Cosigner also re-derives the sighash from the proposed tx + reconstructed prevout and refuses if it doesn't match the request's `sighash`. Pre-this-rule cosigners blind-signed whatever sighash arrived. |

---

## Fee policy (advertised but mostly soft)

| Rule | Layer | Source | Notes |
|---|---|---|---|
| `DepositOpen` fees meet operator-advertised `min_fee_bps`/`min_fee_fixed` | 4 | `node/request_handlers/deposits.rs:245-250`, `operator_policy.rs` | Operator CLI / cosigner refusal. **Bypass risk yes** — a hostile operator can publish a `DepositOpen` with sub-min fees and `apply` accepts it; only honest cosigners' refusal stops it gathering majority. |
| `FeeChange.effective_block` becomes active once `block_height ≥ effective_block` | 1 | `ledger_state.rs:301-309` (`FeeChange`) + `FeeCollect` apply | Stored in `pending_fee_change`. |
| `fee_change_after_blocks` / `fee_change_notice_blocks` / `fee_change_limit_bps` per-deposit caps | (parameters stored, enforcement not surfaced) | `ledger_state.rs::apply` for `DepositOpen` records them; `FeeChange` apply does not check | **Status uncertain — likely no hard enforcement currently.** Honest cosigners may refuse via policy. |
| `max_fee_period` per quorum member | (advertised on `QuorumMember`; cosigner-policy boundary) | — | **Status uncertain.** |

---

## On-chain coupling

The state machine accepts `QuorumBegin`'s declared `(amount, collateral_amount, new_outpoint_txid:vout, reserves_id)` verbatim. **Nothing in `apply` validates that the UTXO actually exists with that value, that the script matches `reserves_id`, or that the spending input was the previous `QuorumBegin`'s output.**

| Check | Layer | Where |
|---|---|---|
| Recorded UTXO exists on-chain at declared txid:vout | external | `validate-relay` tool (`deposits-tools/src/bin/validate-relay.rs`) calls Esplora |
| Recorded UTXO sat value equals `(amount + collateral_amount) / 1000` | external | same |
| The most recent `QuorumBegin`'s UTXO is unspent; earlier ones are spent (rotation chain) | external | same |
| Reserves address matches the tapscript derived from `quorum_members + quorum_expiry + ruleset` | external | `validate-relay` retries each known ruleset and picks the matching one |

These are deliberately external — the protocol crate is `no_std`-friendly and Bitcoin-RPC-free. `validate-relay` exists to run the cross-check in batch.

---

## Cooperative refund gate (recovery refund)

`deposits-node recovery refund <ledger>` is the manual NeverFunded recovery path. It gates aggressively to avoid running on a healthy ledger:

| Refusal reason | Source | When |
|---|---|---|
| `"reserves UTXO has unspent funds"` / `"reserves UTXO is funded"` | `node_cli/recovery.rs` (NeverFunded gate) | Canonical block — the reserves UTXO is still on-chain unspent, so by definition we're not in NeverFunded territory. |
| `"No LedgerOpen at seq 0"` | recovery flow's relay-side replay | Relay-side replay missed genesis. Indicates an incomplete replay rather than a valid refund target. |
| `"lack replacement_collateral"` | recovery flow's RC-readiness check | No quorum members have declared `replacement_collateral` via `DisputeArmed`; refund can't fund its own miner fees + outputs. Fires when the reserves UTXO has already been spent into ledger ops (normal post-setup state). |
| `"missing signatures for inputs: …"` | cooperative-refund-sign request timeout | At least one quorum member's daemon didn't respond to the `cooperative_refund_sign` request within the configured `--timeout`. Treated as a soft failure — the gate worked, the refund just couldn't gather majority. |

Any of these refusals are evidence the gate fired correctly. Tests assert the exit is non-zero AND that one of these markers appears in stdout/stderr.

---

## Replacement-collateral declarations (DEP-03)

| Rule | Layer | Source |
|---|---|---|
| `DisputeArmed` carries optional `replacement_collateral` (`txid`, `vout`, `amount`) all-or-nothing | 4 (TLV codec) | `messages/tlv_codec.rs` (RC1-RC10 rollout); `WinnerCollateralDeviation` fraud verifier audits the eventual claim TX matches |
| Replacement collateral input is op-key P2WPKH | 4 | (constraint per memory; runtime-enforced by claim-TX builder, not `apply`) |

The fraud-verifier path (`WinnerCollateralDeviation`) is the enforcement mechanism — `apply` records the declaration, the watcher disputes a deviating claim TX.

---

## Where each layer's code lives

```
deposits-protocol/src/types/ledger_state.rs    layer 1 (apply) + layer 3 (check_conformance)
deposits-protocol/src/types/conformance.rs     layer 3 violation enum
deposits-core/src/dep16/authorizer.rs          layer 3 ECDSA witness verifier (Dep16Authorizer)
deposits-core/src/ledger.rs                    layer 2 (validate_incoming_update,
                                                        validate_for_cosign, checked_apply)
deposits-core/src/operation_validation.rs      layer 4 pure per-op checks
deposits-core/src/message_validation.rs        layer 4 message-level (currently dispatches
                                                        per-op to operation_validation)
deposits-core/src/validation.rs                layer 4 reserves/balance/business-rule helpers
deposits-node/src/node/request_handlers/**     layer 4 operator-side gating; admin auth
deposits-node/src/node/auto_tasks.rs           layer 4 9 periodic auto-tasks
                                                        (see "Auto-task family" below)
deposits-node/src/node/ledger_queries.rs       layer 4 rotate_reserves_to_quorum
deposits-node/src/operator_policy.rs           layer 4 advertisement-vs-proposal matching
deposits-node/src/operator_drips.rs            layer 4 drip plan registry
deposits-tools/src/bin/validate-relay.rs       external on-chain coupling
```

---

## Admin authentication

| Check | Source | Notes |
|---|---|---|
| `check_admin_authorized` accepts the request iff its inner-rumor `pubkey` equals either the operator's xonly pubkey or the configured admin pubkey | `request_handlers/mod.rs:118-143` | Used by every `process_admin_*_request` handler. Non-admin requests are rejected with `"admin request must be gift-wrapped"` or signature-mismatch. |
| Admin pubkey loaded from `<data_dir>/admin.npub` (bech32 or 64-char hex) at daemon startup | `node/init.rs:358-379` | Optional. Missing file = no admin delegation; only the operator's own key authorizes admin ops. Reload requires daemon restart. |
| Hub-side admin RPC (`deposits-hub/src/admin_client.rs`) builds the same gift-wrapped Kind 20101 envelope, signed with the hub's nostr secret | `admin_client.rs::send_admin_request` | The hub's pubkey is what the operator drops into `admin.npub`. Wire shape mirrors `deposits-node`'s `send_admin_daemon_request`. |

---

## Auto-task family

`auto_tasks.rs` defines a family of periodic tasks dispatched from `node/main_loop.rs:1203-1282` every 5–60 seconds (5s in `--fast-poll`, 60s otherwise). Each runs under a 10-second `timed_periodic!()` budget; long-running tasks (e.g. `auto_quorum_refresh`) spawn detached background work.

| Task | Pause marker | What it commits |
|---|---|---|
| `auto_complete_deposits` | — | Wallet poll → signed deposit-offer completion |
| `auto_credit_received_payments` | — | LDK invoice settled → `InvoiceCredit` (this is the *only* path that requires LDK) |
| `auto_complete_outbound_payments` | — | LDK payment result → `InvoiceFulfill` / `InvoiceFail` |
| `auto_complete_withdrawals` | — | Broadcasts locked withdrawals; commits `OnchainFulfill` |
| `auto_collect_fees` | — | Per-deposit `FeeCollect` at the configured period |
| `auto_timeout_transfers` | — | Expired `TransferLock` → `TransferFail` (rate-limited) |
| `auto_quorum_refresh` | `.pause_auto_quorum_refresh` | Rotates the quorum when expiry looms; spawns per-ledger refresh |
| `auto_dispute_expired_quorums` | `.pause_auto_dispute_actions` | Fork-branch `DisputeEnter` past expiry + grace |
| `auto_drip_self_liquidity` | `.pause_auto_drip_self_liquidity` | Opens/funds/drains operator buffer deposits per drip plan |

Pause markers are file-presence-based so operators can disable a task without restarting the daemon. Test/recovery flows lean heavily on these.

---

## Known gaps surfaced by this audit

These are observations from the audit, not fixes. Listed for follow-up triage; each "bypass risk yes" above is a candidate.

1. **Reserves caps and credit-vs-collateral are layer 4 only.** A hostile operator can publish out-of-bounds `LedgerOpen` reserves or in-quorum credits exceeding collateral; honest cosigner refusal is the only shield. `check_conformance` covers credit-vs-reserves (the reserves side) but not collateral.
2. **Unknown `protocol_version` is silently accepted by `apply`.** It pins `active_ruleset_name` to the unknown name; readers fall back to legacy via `resolve_or_legacy` at lookup time. No layer-1 reject.
3. **`receive_requires_sig` enforcement is operator-side only.** Cosigner refusal not wired through.
4. **`fee_change_*` per-deposit caps are stored but not checked at `FeeChange` apply.** Honest cosigners may enforce policy; needs verification.
5. **`QuorumBegin.quorum_expiry` vs members' `membership_until`** — no hard layer-1 check found.
6. **`QuorumAddMember.member_response` integrity is layer 4.** A hand-rolled `QuorumAddMember` with a bogus blob (or no blob) bypasses the binding; the resulting `QuorumMember.supported_rulesets` is whatever the operator wrote. Layer 1 only enforces the *consequence* (the ruleset gate at `QuorumBegin`).
7. **`message_validation.rs` carries a TODO for "demo-specific fake invoice check"** — documented misplacement.
8. **Cosigners can't distinguish synthetic from real Lightning settlements.** `InvoiceCredit` accepts any `payment_hash`; `InvoiceLock`+`Fulfill` accepts any `(preimage, payment_id)` pair where `SHA256(preimage) == payment_id`. This is what enables operator-owned buffer deposits and the liquidity-drip auto-task. By design — see the synthetic-ops section above — but worth restating here so it doesn't surprise an auditor.

## Closed gaps (resolved during recent work)

- **Drip and buffer-deposit infra were parallel.** Two registries (`buffer_indices.json` at 1M+, `operator_drips.json` at 2M+), two impls of open/credit/drain — `auto_drip_self_liquidity` duplicated `process_admin_buffer_*_request` bodies. Refactored (commit `d1214f92`) so drip plans reference a `buffer_index` and call shared `internal_buffer_open/fill/drain/balance_msats` helpers. One registry, one code path.
- **`admin/buffer-drain` produced sigs the authorizer rejected.** Handler called `signer.bip340_sign(...)` (Schnorr) but `Dep16Authorizer` uses ECDSA. No test exercised the path past sig verification so the bug stayed hidden. Fixed in commit `8a423b44`; the same bug had snuck into the drip's drain step (fixed in `4be74027`).
